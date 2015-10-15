# -*- encoding: utf-8 -*-

require 'rubygems'
require 'fluent/plugin/out_elasticsearch'
require 'aws-sdk'
require 'faraday_middleware'
require 'faraday_middleware/aws_signers_v4'


module Fluent
  class AwsElasticsearchServiceOutput < ElasticsearchOutput

    Plugin.register_output('aws-elasticsearch-service', self)

    config_section :endpoint do
      config_param :region, :string
      config_param :url, :string
      config_param :access_key_id, :string, :default => ""
      config_param :secret_access_key, :string, :default => ""
    end

#    config_param :logstash_format, :bool, :default => false
#    config_param :logstash_prefix, :string, :default => "logstash"
#    config_param :logstash_dateformat, :string, :default => "%Y.%m.%d"
#    config_param :utc_index, :bool, :default => true
#    config_param :type_name, :string, :default => "fluentd"
#    config_param :index_name, :string, :default => "fluentd"
#    config_param :id_key, :string, :default => nil
#    config_param :parent_key, :string, :default => nil
#    config_param :request_timeout, :time, :default => 5
#    config_param :reload_connections, :bool, :default => true
#    config_param :reload_on_failure, :bool, :default => false
#    config_param :time_key, :string, :default => nil
#    config_param :ssl_verify , :bool, :default => true
#    config_param :client_key, :string, :default => nil
#    config_param :client_cert, :string, :default => nil
#    config_param :client_key_pass, :string, :default => nil
#    config_param :ca_file, :string, :default => nil
# 
#    include Fluent::SetTagKeyMixin
#    config_set_default :include_tag_key, false
#
#    def client
#      @_es ||=
#        begin
#          excon_options = { client_key: @client_key, client_cert: @client_cert, client_key_pass: @client_key_pass }
#          adapter_conf = lambda {|f| f.adapter :excon, excon_options }
#          #adapter_conf = lambda {|f| f.adapter :net_http}
#          transport = ElasticsearchOutput::Elasticsearch::Transport::Transport::HTTP::Faraday.new(
#            get_connection_options.merge(
#            options: {
#              reload_connections: @reload_connections,
#              reload_on_failure: @reload_on_failure,
#              retry_on_failure: 5,
#              transport_options: {
#                request: { timeout: @request_timeout },
#                ssl: { verify: @ssl_verify, ca_file: @ca_file }
#              }
#            }), &adapter_conf)
#          es = Elasticsearch::Client.new transport: transport
# 
#          begin
#            raise ElasticsearchOutput::ConnectionFailure, "Can not reach Elasticsearch cluster (#{connection_options_description})!" unless es.ping
#          rescue *es.transport.host_unreachable_exceptions => e
#            raise ElasticsearchOutput::ConnectionFailure, "Can not reach Elasticsearch cluster (#{connection_options_description})! #{e.message}"
#          end
# 
#          log.info "Connection opened to Elasticsearch cluster => #{connection_options_description}"
#          es
#        end
#    end

    def get_connection_options
      raise "`endpoint` require." if @endpoint.empty?
      
      hosts =
        begin
          @endpoint.map do |ep|
            uri = URI(ep[:url])
            host = %w(user password path).inject(host: uri.host, port: uri.port, scheme: uri.scheme) do |hash, key|
              hash[key.to_sym] = uri.public_send(key) unless uri.public_send(key).nil? || uri.public_send(key) == ''
              hash
            end

            host[:aws_elasticsearch_service] = {
              :credentials => credentials(ep[:access_key_id], ep[:secret_access_key]),
              :region => ep[:region]
            }
            
            host
          end
        end
      
      {
        hosts: hosts
      }
    end


    private

    def credentials(access_key, secret_key)
      credentials = nil

      if access_key.empty? or secret_key.empty?
        credentials   = Aws::InstanceProfileCredentials.new.credentials
        credentials ||= Aws::SharedCredentials.new.credentials
      end

      credentials ||= Aws::Credentials.new access_key, secret_key
      credentials
    end


    class ElasticsearchOutput::Elasticsearch::Transport::Transport::HTTP::Faraday
      # Builds and returns a collection of connections.
      #
      # @return [Connections::Collection]
      #
      def __build_connections
        Elasticsearch::Transport::Transport::Connections::Collection.new(
          :connections => hosts.map { |host|
            host[:protocol]   = host[:scheme] || DEFAULT_PROTOCOL
            host[:port]     ||= DEFAULT_PORT
            url               = __full_url(host)

            Elasticsearch::Transport::Transport::Connections::Connection.new(
              :host => host,
              :connection => ::Faraday::Connection.new(
                url,
                (options[:transport_options] || {}),
                &faraday_conf(host, &@block)
              ),
              :options => host[:connection_options]
            )
          },
          :selector_class => options[:selector_class],
          :selector => options[:selector]
        )
      end

      def faraday_conf(host, &block)
        lambda do |faraday|
          if host[:aws_elasticsearch_service]
            faraday.request :aws_signers_v4,
                            credentials: host[:aws_elasticsearch_service][:credentials],
                            service_name: 'es',
                            region: host[:aws_elasticsearch_service][:region]
          end
          block.call faraday
        end
      end
    end

  end
end
