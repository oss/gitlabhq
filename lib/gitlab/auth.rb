require 'yaml'
module Gitlab
  class Auth
    def find_for_ldap_auth(auth, signed_in_resource = nil)
      uid = auth.info.uid
      provider = auth.provider
      email = auth.info.email.downcase unless auth.info.email.nil?
	  
	  if email.nil?
		  config = YAML.load_file("/home/gitlab/gitlab/config/gitlab.yml")
		  email = auth.info.nickname + "@" + config["ldap"]["email_domain"]
	  
	  end
      raise OmniAuth::Error, "LDAP accounts must provide an uid" if uid.nil?

      if @user = User.find_by_extern_uid_and_provider(uid, provider)
        @user
      elsif @user = User.find_by_email(email)
        log.info "Updating legacy LDAP user #{email} with extern_uid => #{uid}"
        @user.update_attributes(:extern_uid => uid, :provider => provider)
        @user
      else
        create_from_omniauth(auth, true)
      end
    end

    def create_from_omniauth(auth, ldap = false)
      provider = auth.provider
      uid = auth.info.uid || auth.uid
      name = auth.info.name.force_encoding("utf-8")
      email = auth.info.email.downcase unless auth.info.email.nil?
	  
	  if email.nil?
		  config = YAML.load_file("/home/gitlab/gitlab/config/gitlab.yml")
		  email = auth.info.nickname + "@" + config["ldap"]["email_domain"]
	  end

      ldap_prefix = ldap ? '(LDAP) ' : ''
      #raise OmniAuth::Error, "#{ldap_prefix}#{provider} does not provide an email"\
      #  " address" if auth.info.email.blank?

      log.info "#{ldap_prefix}Creating user from #{provider} login"\
        " {uid => #{uid}, name => #{name}, email => #{email}}"
      password = Devise.friendly_token[0, 8].downcase
      @user = User.new({
        extern_uid: uid,
        provider: provider,
        name: name,
        username: email.match(/^[^@]*/)[0],
        email: email,
        password: password,
        password_confirmation: password,
        projects_limit: Gitlab.config.gitlab.default_projects_limit,
      }, as: :admin)
      if Gitlab.config.omniauth['block_auto_created_users'] && !ldap
        @user.blocked = true
      end
	  gid=Integer(auth.info.gid)
	  config=YAML.load_file("/home/gitlab/gitlab/config/gitlab.yml")
	  admin_gids=config["ldap"]["admin_gids"]
	  for num in admin_gids
		if gid==Integer(num)
		  @user.admin = true
		  break
		end
	  end
      @user.save!
      @user
    end

    def find_or_new_for_omniauth(auth)
      provider, uid = auth.provider, auth.uid
      email = auth.info.email.downcase unless auth.info.email.nil?
	  
	  if email.nil?
		  config = YAML.load_file("/home/gitlab/gitlab/config/gitlab.yml")
		  email = auth.info.nickname + "@" + config["ldap"]["email_domain"]
	  end

      if @user = User.find_by_provider_and_extern_uid(provider, uid)
        @user
      elsif @user = User.find_by_email(email)
        @user.update_attributes(:extern_uid => uid, :provider => provider)
        @user
      else
        if Gitlab.config.omniauth['allow_single_sign_on']
          @user = create_from_omniauth(auth)
          @user
        end
      end
    end

    def log
      Gitlab::AppLogger
    end
  end
end
