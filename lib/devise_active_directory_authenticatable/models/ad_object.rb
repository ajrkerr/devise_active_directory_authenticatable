module Devise
  #Basic functions and shared methods for AD objects in ActiveRecord
  module AdObject
    extend ActiveSupport::Concern

    Logger = DeviseActiveDirectoryAuthenticatable::Logger

    def attr_map
      @attr_map ||= ::Devise.ad_attr_mapping[klass.devise_model_name.to_sym]
    end

    def klass
      self.class
    end

    def ad_obj
      @ad_obj ||= klass.find_activedirectory_objs(:objectguid => self.objectguid).first
    end

    # Update the attributes of the current object from the AD
    # Defaults to current user if no parameters given
    # def activedirectory_sync! params = {}
    #   params[:objectguid] = self.objectguid if params.empty?
    #   @ad_obj ||= params[:object] || klass.find_activedirectory_objs(params).first
      
    #   attr_map.each do |local_attr, active_directory_attr|
    #     self[local_attr] = @ad_obj[active_directory_attr]
    #   end

    #   update_memberships
    # end

    # Update the attributes of the current object from the AD
    # Defaults to current user if no parameters given
    def copy_from_activedirectory! params = {}
      #Allows us to change what ad object is bound to this user
      @ad_obj = klass.find_activedirectory_objs(params).first unless params.empty?

      unless @ad_obj.nil?
        attr_map.each do |local_attr, active_directory_attr|
          self[local_attr] = @ad_obj[active_directory_attr]
        end

        update_memberships
      end
    end

    ##
    # Updates the members and memberofs stored in the database
    # and by update, I mean overwrite
    # TODO find a way to update, or at least not molest non-AD associations
    def update_memberships
      update_children
      update_parents
    end

    def update_children
      #Set the members
      if ad_obj[:member].is_a? Array
        update_membership(ad_obj[:member], klass.member_users) if defined? klass.member_users
        update_membership(ad_obj[:member], klass.member_groups) if defined? klass.member_groups
      end
    end

    def update_parents
      # MemberOf Relationship
      if ad_obj[:memberof].is_a? Array and defined? klass.memberof
        update_membership(ad_obj[:memberof], klass.memberof)
      end
    end

    def update_membership ad_objs, params
      # Create the objects of the right type, then sets them
      klass = params[:class]
      field = params[:field]

      ad_objs = klass.find_from_activedirectory(:object => ad_objs)
      self.send "#{field}=", ad_objs
    end

    module ClassMethods

      attr_accessor :member_groups, :member_users, :memberof

      def login_with
        ::Devise.authentication_keys.first
      end

      def set_devise_ad_options field, params = {}
        ret = {}
        ret[:field] = field.to_s
        ret[:class_name] = (params[:class_name] || field).to_s.classify
        ret[:class] = Kernel.const_get(ret[:class_name])

        unless ret[:class].include? AdObject
          raise "#{ret[:class_name]} does not include any of the Devise Active Directory modules.  Please consult the documentation." 
        end

        return ret
      end

      def devise_ad_memberof field, params = {}
        @memberof = set_devise_ad_options field, params
      end

      def devise_ad_member_groups field, params = {}
        @member_groups = set_devise_ad_options field, params
      end

      def devise_ad_member_users field, params = {}
        @member_users = set_devise_ad_options field, params
      end
  
      def devise_model_name
        @devise_model ||= devise_model.name[/.*::(.*)/, 1]
      end

      def activedirectory_class_name
        @ad_class ||= activedirectory_class.name[/.*::(.*)/, 1]
      end


      #Search based on GUID, DN or Username primarily
      def find_activedirectory_objs local_params = {}
        #Sometimes we're provide the objects
        if local_params.key? :object
          return [local_params[:object]] unless local_params[:object].kind_of? Array
          return local_params[:object]
        end

        #Reverse mappings for user
        ad_params = local_attrs_to_ad(local_params)

        activedirectory_class.find(:all, ad_params)
      end

      def find_from_activedirectory local_params = {}
        ad_objs = find_activedirectory_objs local_params
        guids = ad_objs.collect { |obj| obj[:objectguid] }
        where(:objectguid => guids)
      end

      ##
      # Does a search using AD terms and either finds the corresponding
      # object in the database, or creates it
      # TODO change attributes to not be statically mapped to objectguid
      def find_or_create_from_activedirectory local_params = {}
        ad_objs = find_activedirectory_objs local_params
        local_objs = []

        #Grab all of the objects in one query by GUID for efficiency
        guids = ad_objs.collect { |obj| obj[:objectguid] }
        db_objs_by_guid = {}

        #Make a hash map to do quick lookups
        where(:objectguid => guids).each do |db_obj|
          db_objs_by_guid[db_obj.objectguid] = db_obj
        end

        ad_objs.each do |ad_obj|
          guid = ad_obj[:objectguid]
          obj = db_objs_by_guid[guid] || new
          obj.copy_from_activedirectory!(:object => ad_obj) if obj.new_record?

          local_objs << obj
        end

        local_objs
      end

      def sync_all
        return false unless connected_to_activedirectory?

        db_objs = find_or_create_from_activedirectory

        ActiveRecord::Base.transaction do
          #Save the new ones
          db_objs.each { |obj| obj.save if obj.new_record? }

          #Then update the memberships
          #If we're updating all of them, then updating just the parents will do
          db_objs.each do |obj| 
            obj.update_parents
          end
        end
      end

      ##
      # Checks to see if a conection with AD has been established
      def connected_to_activedirectory?
        ActiveDirectory::Base.connected?
      end

      ##
      # Sets the username and password for the connection
      # params {:username => 'joe.user', :password => 'top_secret' }
      def set_activedirectory_credentials(params = {})
        #Used for username and password only
        ::Devise.ad_settings[:auth].merge! params
      end

      ##
      # Attempts to connect with the activedirectory based on the configuration options
      def activedirectory_connect
        ActiveDirectory::Base.enable_cache if ::Devise.ad_caching
        ActiveDirectory::Base.setup(::Devise.ad_settings)
        raise DeviseActiveDirectoryAuthenticatable::ActiveDirectoryException, "Invalid Username or Password" unless ActiveDirectory::Base.connected?
      end

      private

      #TODO switch from reverse to rassoc to allow for multiple mappings
      def ad_field_to_local field_name
        @ad_to_local_map ||= ::Devise.ad_attr_mapping[devise_model_name.to_sym].invert
        return (@ad_to_local_map.has_key? field_name) ? @ad_to_local_map[field_name] : field_name
      end

      #TODO switch from reverse to rassoc to allow for multiple mappings
      def local_field_to_ad field_name
        @local_to_ad_map ||= ::Devise.ad_attr_mapping[devise_model_name.to_sym]
        return (@local_to_ad_map.has_key? field_name) ? @local_to_ad_map[field_name] : field_name
      end

      def ad_attrs_to_local ad_attrs
        local_attrs = {}
        ad_attrs.each do |ad_key, value|
          local_key = ad_field_to_local(ad_key)
          local_attrs[local_key] = value
        end
        local_attrs
      end

      def local_attrs_to_ad local_attrs
        ad_attrs = {}
        local_attrs.each do |local_key, value|
          ad_key = local_field_to_ad(local_key)
          ad_attrs[ad_key] = value
        end
        ad_attrs
      end

    end
  end
end
