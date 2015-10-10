# -*- encoding: utf-8 -*-

require 'rubygems'
require 'fluent/plugin/out_elasticsearch'
require 'aws-sdk'
require 'openssl'

module Fluent
  class AwsElasticsearchServiceOutput < ElasticsearchOutput

    Plugin.register_output('aws-elasticsearch-service', self)

    config_section :endpoint do
      config_param :region, :string
      config_param :url, :string
      config_param :access_key, :string
      config_param :secret_key, :string
    end

    config_param :logstash_format, :bool, :default => false
    config_param :logstash_prefix, :string, :default => "logstash"
    config_param :logstash_dateformat, :string, :default => "%Y.%m.%d"
    config_param :utc_index, :bool, :default => true
    config_param :type_name, :string, :default => "fluentd"
    config_param :index_name, :string, :default => "fluentd"
    config_param :id_key, :string, :default => nil
    config_param :parent_key, :string, :default => nil
    config_param :request_timeout, :time, :default => 5
    config_param :reload_connections, :bool, :default => true
    config_param :reload_on_failure, :bool, :default => false
    config_param :time_key, :string, :default => nil
    config_param :ssl_verify , :bool, :default => true
    config_param :client_key, :string, :default => nil
    config_param :client_cert, :string, :default => nil
    config_param :client_key_pass, :string, :default => nil
    config_param :ca_file, :string, :default => nil

    include Fluent::SetTagKeyMixin
    config_set_default :include_tag_key, false

    def client
      @_es ||= begin
                 excon_options = { client_key: @client_key, client_cert: @client_cert, client_key_pass: @client_key_pass }
                 adapter_conf = lambda {|f| f.adapter :excon, excon_options }
                 transport = Faraday.new(get_connection_options.merge(
                                                                                     options: {
                                                                                       reload_connections: @reload_connections,
                                                                                       reload_on_failure: @reload_on_failure,
                                                                                       retry_on_failure: 5,
                                                                                       transport_options: {
                                                                                         request: { timeout: @request_timeout },
                                                                                         ssl: { verify: @ssl_verify, ca_file: @ca_file }
                                                                                       }
                                                                                     }), &adapter_conf)
                 es = Elasticsearch::Client.new transport: transport
                 
                 begin
                   raise ConnectionFailure, "Can not reach Elasticsearch cluster (#{connection_options_description})!" unless es.ping
                 rescue *es.transport.host_unreachable_exceptions => e
                   raise ConnectionFailure, "Can not reach Elasticsearch cluster (#{connection_options_description})! #{e.message}"
                 end

                 log.info "Connection opened to Elasticsearch cluster => #{connection_options_description}"
                 es
               end
    end

    def get_connection_options
      raise "`endpoint` require." if @endpoint.empty?
      
      hosts =
        begin
          @endpoint.map do |ep|
            uri = URI(ep.url)
            host = %w(user password path).inject(host: uri.host, port: uri.port, scheme: uri.scheme) do |hash, key|
              hash[key.to_sym] = uri.public_send(key) unless uri.public_send(key).nil? || uri.public_send(key) == ''
              hash
            end

            access_key = if ep.access_key
                           ep.access_key
                         else
                           credentials().access_key_id
                         end
#            secret_key = if ep.secret_key
#                           ep.secret_key
#                         else
#                           credentials().secret_access_key
#                         end

            host[:connection_options] = {
              :access_key => access_key,
#              :secret_key => secret_key
              :region => ep.region
            }
            host
          end
        end
      
      {
        hosts: hosts
      }
    end

    def credentials
      @aws_credentials ||=
        begin
          instance = Aws::InstanceProfileCredentials.new
          credentials = if instance.credentials.empty?
                          shared = Aws::SharedCredentials.new
                          shared.credentials
                        else
                          instance.credentials
                        end
          
          credentials
        end
    end


    class Faraday < Elasticsearch::Transport::Transport::HTTP::Faraday
      # Performs the request by invoking {Transport::Base#perform_request} with a block.
      #
      # @return [Response]
      # @see    Transport::Base#perform_request
      #
      def perform_request(method, path, params={}, body=nil)
        super do |connection, url|
          
          response = connection.connection.run_request(
            method.downcase.to_sym,
            url,
            ( body ? __convert_to_json(body) : nil ),
            {
              Authorization: authorization(connection)
            }
          )
          Response.new response.status, response.body, response.headers
        end
      end

      # Builds and returns a collection of connections.
      #
      # @return [Connections::Collection]
      #
      def __build_connections
        Connections::Collection.new(
          :connections => hosts.map { |host|
            host[:protocol]   = host[:scheme] || Elasticsearch::Transport::Transport::Base::DEFAULT_PROTOCOL
            host[:port]     ||= Elasticsearch::Transport::Transport::Base::DEFAULT_PORT
            url               = __full_url(host)

            Connections::Connection.new(
              :host => host,
              :connection => ::Faraday::Connection.new(
                url,
                (options[:transport_options] || {}),
                &@block
              ),
              :options => host[:connection_options]
            )
          },
          :selector_class => options[:selector_class],
          :selector => options[:selector]
        )
      end


      def authorization()

      end

      def signature(connection, datestring)
        getSignatureKey(
          
        )
      end

      # 
      #
      # @see https://docs.aws.amazon.com/ja_jp/general/latest/gr/signature-v4-examples.html#signature-v4-examples-ruby
      #
      def getSignatureKey key, dateStamp, regionName, serviceName = 'es'
        kDate    = OpenSSL::HMAC.digest('sha256', "AWS4" + key, dateStamp)
        kRegion  = OpenSSL::HMAC.digest('sha256', kDate, regionName)
        kService = OpenSSL::HMAC.digest('sha256', kRegion, serviceName)
        kSigning = OpenSSL::HMAC.digest('sha256', kService, "aws4_request")
        kSigning
      end
    end

  end
end
