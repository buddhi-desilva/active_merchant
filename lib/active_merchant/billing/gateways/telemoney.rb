# require 'base64'
require 'cgi'
require 'uri'

#####################################################
#####################################################
#####################################################
#TODO: TEMPORY MEASURE ONLY. REMOVE ONCE TESTED
OpenSSL::SSL::VERIFY_PEER = OpenSSL::SSL::VERIFY_NONE
#####################################################
#####################################################
#####################################################

require File.dirname(__FILE__) + '/telemoney/telemoney_codes'

module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    class TelemoneyGateway < Gateway
      include TelemoneyCodes

      class_attribute :mid
      class_attribute :test_url
      class_attribute :live_url
      class_attribute :ref

      self.supported_countries = [ 'SG' ]
      self.supported_cardtypes = [ :visa, :master ]
      self.display_name        = 'Telemoney'
      self.homepage_url        = 'http://telemoney.com.sg'
      self.default_currency    = 'SGD'
      self.money_format        = :dollars

      # ActiveMerchant Transaction types mapped to the Telelmoney internal actions
      # within methods the action names are taken from TRANSACTIONS[__method__.to_sym]
      TRANSACTIONS  = {
        :authorize  => 'auth',
        :capture    => 'capture',
        :purchase   => 'sale',
        :void       => 'void',
        :refund     => 'refund'
      }

      SUPPORTED_CURRENCIES = [ 'SGD', 'MYD', 'USD', 'AUD', 'JPY', 'HKD' ]

      #Payment types / Card types
      PAY_TYPES = {
        '2'     =>  'master',  # Master Credit Card
        '3'     =>  'visa',  # VISA Credit Card
        '5'     =>  'american_express',  # AMEX Card
        '23'    =>  'jcb', # JCB Credit Card
        '22'    =>  'diners_club', # Diners Credit Card
        '60'    =>  'china_union_pay', # China Union Pay Credit Card

        #For DBS ONUS transactions
        '210'   =>  'dbs_master', # DBS Master Credit Card
        '310'   =>  'dbs_visa', # DBS VISA Credit Card
        '510'   =>  'dbs_amex', # DBS AMEX Card
        '2210'  =>  'dbs_diners' # DBS Diners Credit Card
      }



      def initialize(options = {})
        requires!(options, :mid, :test_url, :live_url)

        self.mid = options.delete(:mid)
        self.ref = !options[:ref].blank? ? options[:ref].to_s : unique_transaction_number
        self.test_url = options.delete(:test_url)
        self.live_url = options.delete(:live_url)

        super
      end

      def authorize(money, credit_card, options = {})
        post = {}
        add_user_fields(post, options)
        add_amount_and_currency(post, money, options)
        add_credit_card(post, credit_card)
        commit(post)
      end

      def capture(money, authorization, options = {})
        post = {}
        auth_string_codes = get_authorization_paytype_and_subtranstype(authorization)
        self.ref = auth_string_codes[:authorization]
        post[:paytype] = auth_string_codes[:paytype]
        post[:ccdate] = auth_string_codes[:ccdate]
        add_amount_and_currency(post, money, options)
        commit(post)
      end

      def purchase(money, credit_card, options = {})
        post = {}
        add_user_fields(post, options)
        add_amount_and_currency(post, money, options)
        add_credit_card(post, credit_card)
        commit(post)
      end

      # Not tested. Since it's mandatory to provide credit card number
      # it can be a big security vulnerability.
      def refund(credit_card, authorization, options = {})
        post = {}

        auth_string_codes = get_authorization_paytype_and_subtranstype(authorization)
        self.ref = auth_string_codes[:authorization]
        post[:paytype] = auth_string_codes[:paytype]
        post[:ccdate] = auth_string_codes[:ccdate]
        post[:subtranstype] = auth_string_codes[:subtranstype]
        post[:refundauthcode] = options[:refundauthcode]
        add_credit_card(post, credit_card)
        commit(post)
      end

      def void(authorization, options = {})
        post = {}
        auth_string_codes = get_authorization_paytype_and_subtranstype(authorization)
        self.ref = auth_string_codes[:authorization]
        post[:paytype] = auth_string_codes[:paytype]
        post[:ccdate] = auth_string_codes[:ccdate]
        post[:cur] = auth_string_codes[:cur]
        post[:amt] = auth_string_codes[:amt]
        post[:subtranstype] = auth_string_codes[:subtranstype]

        commit(post)
      end




      private
      ##################################################

        def commit(parameters)
           # Gets the caller method name and then grab the Telemoney action name from
           # TRANSACTIONS hash.
          parameters[:transtype] = TRANSACTIONS[caller[0][/`.*'/][1..-2].to_sym]
          parameters[:mid] = self.mid
          parameters[:ref] = self.ref.to_s

          response = CGI::parse( ssl_post(self.live_url, post_data(parameters)) )

          #flatten the response which is received as an arrays within an array
          response.each do |key, value|
            response[key] = value.join
          end

          #Store authorization code + other necessary info in the auth string
          authorization_hash = {}
          authorization_hash[:authorization] = response["TM_RefNo"]
          authorization_hash[:paytype] = response["TM_PaymentType"]
          authorization_hash[:subtranstype] = response["TM_TrnType"]
          authorization_hash[:ccdate] = parameters[:ccdate]
          authorization_hash[:cur] = parameters[:cur]
          authorization_hash[:amt] = parameters[:amt]
          authorization_hash_string = authorization_hash.map{|key, value| "#{key}=#{value}"}.join('---')


          Response.new(response["TM_Status"] == 'YES', message_from(response), response,
            :test => test?,
            # This is a hack to avoid extra code/calculations or possible db changes to the
            # user/coder. Telemoney requires an additional paytype parameter provided and it
            # refers to the card type. Which I feel as an extra unnecessary step that could be done
            # internally within telemoney servers while putting efforts to reinforce the security
            # i.e: Telemoney doesn't require a password to do transactions. TM_TrnType is also added to the
            # autho response, since it's required for refunds as 'subtranstype' variable to process the refund.
            # Upon receiving the auth code, we can use assign_authorization_and_paytype to split the
            # code into authrization and paytype.
            :authorization => authorization_hash_string
          )


        end

        def message_from(response)
          if response["TM_Status"] == "YES"
            return 'Success'
          else
            return 'Unspecified error' if response["TM_ErrorMsg"].blank?
            return response["TM_ErrorMsg"]
          end
        end

        def post_data(parameters = {})
          parameters.collect { |key, value| "#{key}=#{CGI.escape(value.to_s)}" }.join("&")
        end

        def add_credit_card(post, credit_card)
          post[:ccnum]  = credit_card.number
          post[:cccvv] = credit_card.verification_value if credit_card.verification_value?
          post[:ccdate]  = "#{format(credit_card.year, :two_digits)}#{format(credit_card.month, :two_digits)}"
          post[:paytype] = pay_type?(credit_card.number).to_s
        end

        def add_amount_and_currency(post, money, options = {})
          post[:amt] = amount(money)
          post[:cur] = options[:currency] || self.default_currency
        end

        def add_user_fields(post, options = {})
          post[:userfield1] = options[:userfield1] if options[:userfield1]
          post[:userfield2] = options[:userfield2] if options[:userfield2]
          post[:userfield3] = options[:userfield3] if options[:userfield3]
          post[:userfield4] = options[:userfield4] if options[:userfield4]
        end


        def get_authorization_paytype_and_subtranstype(authorization_string)
          authorization_hash = {}
          Hash[*authorization_string.split(/=|---/)].map{|key, value| authorization_hash[key.to_sym] = value}
          authorization_hash
        end

        def pay_type?(number)
          # checks if there's a matching brand and returns the paytype.
          if card_brand = CreditCard.brand?(number)
            PAY_TYPES.each do |pay_type, company|
              return pay_type.to_i if company == card_brand
            end
          end
          return nil
        end

        # Telemoney requires a unique transaction number and we are generating it
        # within our class than expecting it from outside. However if there's an
        # outside UTRN it'll be used
        def unique_transaction_number
          chars = [('a'..'z'),('A'..'Z')].map{|i| i.to_a}.flatten
          string = (0...10).map{ chars[rand(chars.length)] }.join + Time.now.to_i.to_s
        end

    end
  end
end

