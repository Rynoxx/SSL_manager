<?php
if (ctrl_options::GetSystemOption('apache_changed') == strtolower("true")) {
	WriteSSLConfig();
	/*
		The following three functions have been commented out because they need further testing before going live.
		They're only included so that people who want to can test them.

		WriteProFTPdConfig();
		WritePostfixConfig();
		WriteDovecotConfig();
	*/
}

function getSSLDir($domain, $username){
	$domain1 = str_replace('.', '_', $domain);
	if($domain == ctrl_options::GetSystemOption('sentora_domain')){
		return str_replace("//", "/", str_replace("/panel", "/ssl", ctrl_options::GetSystemOption('sentora_root')));
	}
	else{
		return str_replace("//", "/", ctrl_options::GetSystemOption('hosted_dir') . $username ."/ssl/" . $domain1 . (empty($domain1) ? "" : "/"));
	}
}

function WritePostfixConfig(){
	$domain = ctrl_options::GetSystemOption('sentora_domain');
	$dir = getSSLDir($domain, "");

	if(!is_dir($dir) || !file_exists($dir . $domain . ".key") || !file_exists($dir . $domain . ".crt")){
		return
	}

	$postfixMainConfigPath = str_replace("/panel", "/configs", ctrl_options::GetSystemOption('sentora_root')) . "/postfix/main.cf";
	$postfixMasterConfigPath = str_replace("/panel", "/configs", ctrl_options::GetSystemOption('sentora_root')) . "/postfix/master.cf";

	$write = "";

	if((file_exists($postfixMainConfigPath) && stripos(file_get_contents($postfixMainConfigPath), "#Sentora TLS Config") === false) || !file_exists($postfixMainConfigPath)){
		$write .= "#Sentora TLS Config" . fs_filehandler::NewLine();
		$write .= "smtp_use_tls = yes" . fs_filehandler::NewLine();
		$write .= "smtpd_use_tls = yes" . fs_filehandler::NewLine();
		$write .= "# Disable SSLV3 - POODLE - Begin" . fs_filehandler::NewLine();
		$write .= "smtpd_tls_mandatory_protocols=!SSLv2,!SSLv3" . fs_filehandler::NewLine();
		$write .= "smtp_tls_mandatory_protocols=!SSLv2,!SSLv3" . fs_filehandler::NewLine();
		$write .= "smtpd_tls_protocols=!SSLv2,!SSLv3" . fs_filehandler::NewLine();
		$write .= "smtp_tls_protocols=!SSLv2,!SSLv3" . fs_filehandler::NewLine();
		$write .= "# Disable SSLV3 - POODLE - End" . fs_filehandler::NewLine();
		$write .= "smtpd_tls_auth_only = no" . fs_filehandler::NewLine();
		$write .= "smtpd_tls_security_level = may" . fs_filehandler::NewLine();
		$write .= "smtp_tls_note_starttls_offer = yes" . fs_filehandler::NewLine();
		$write .= "smtpd_tls_loglevel = 1" . fs_filehandler::NewLine();
		$write .= "smtpd_tls_received_header = yes" . fs_filehandler::NewLine();
		$write .= "smtpd_tls_session_cache_timeout = 3600s" . fs_filehandler::NewLine();
		$write .= "tls_random_source = dev:/dev/urandom" . fs_filehandler::NewLine();
		$write .= "smtp_tls_session_cache_database = btree:$data_directory/smtp_tls_session_cache" . fs_filehandler::NewLine();
		$write .= "smtpd_tls_key_file = " . $dir . $domain . ".key" . fs_filehandler::NewLine();
		$write .= "smtpd_tls_cert_file = " . $dir . $domain . ".crt" . fs_filehandler::NewLine();

		if(file_exists("$ssl_dir/intermediate.crt")){
			$write .= "\tsmtpd_tls_CAfile $ssl_dir/intermediate.crt" . fs_filehandler::NewLine();
		}

		$write .= "#Sentora TLS Config END" . fs_filehandler::NewLine();

		file_put_contents($postfixMainConfigPath, $write, FILE_APPEND);
	}

	$write = "";

	if((file_exists($postfixMasterConfigPath) && stripos(file_get_contents($postfixMasterConfigPath), "#Sentora TLS Config") === false) || !file_exists($postfixMasterConfigPath)){
 		$write .= "#Sentora TLS Config" . fs_filehandler::NewLine();
 		$write .= "smtp      inet  n       -       n       -       -       smtpd" . fs_filehandler::NewLine();
 		$write .= " -o smtpd_sasl_auth_enable=yes" . fs_filehandler::NewLine();
 		$write .= " -o receive_override_options=no_address_mappings" . fs_filehandler::NewLine();
 		$write .= " #-o content_filter=smtp-amavis:127.0.0.1:10024" . fs_filehandler::NewLine();
 		$write .= "smtps     inet  n       -       n       -       -       smtpd" . fs_filehandler::NewLine();
 		$write .= " -o smtpd_sasl_auth_enable=yes" . fs_filehandler::NewLine();
 		$write .= " -o smtpd_tls_wrappermode=yes" . fs_filehandler::NewLine();
 		$write .= " -o smtpd_tls_security_level=encrypt" . fs_filehandler::NewLine();
 		$write .= " -o smtpd_etrn_restrictions=reject" . fs_filehandler::NewLine();
 		$write .= " #-o content_filter=smtp-amavis:127.0.0.1:10024" . fs_filehandler::NewLine();
 		$write .= "submission inet n       -       n       -       -       smtpd" . fs_filehandler::NewLine();
 		$write .= " -o smtpd_sasl_auth_enable=yes" . fs_filehandler::NewLine();
 		$write .= " -o smtpd_tls_wrappermode=yes" . fs_filehandler::NewLine();
 		$write .= " -o smtpd_tls_security_level=encrypt" . fs_filehandler::NewLine();
 		$write .= " -o smtpd_etrn_restrictions=reject" . fs_filehandler::NewLine();
 		$write .= " #-o content_filter=smtp-amavis:127.0.0.1:10024" . fs_filehandler::NewLine();
		$write .= "#Sentora TLS Config END" . fs_filehandler::NewLine();

		file_put_contents($postfixMasterConfigPath, $write, FILE_APPEND);
	}
}

function WriteDovecotConfig(){
	$domain = ctrl_options::GetSystemOption('sentora_domain');
	$dir = getSSLDir($domain, "");

	if(!is_dir($dir) || !file_exists($dir . $domain . ".key") || !file_exists($dir . $domain . ".crt")){
		return
	}

	$dovecotConfigPath = str_replace("/panel", "/configs", ctrl_options::GetSystemOption('sentora_root')) . "/dovecot2/dovecot.conf";

	$write = "";

	if((file_exists($dovecotConfigPath) && stripos(file_get_contents($dovecotConfigPath), "#Sentora TLS Config") === false) || !file_exists($dovecotConfigPath)){
		$write = "";
		$write .= "#Sentora TLS Config" . fs_filehandler::NewLine();
		$write .= "!include tls.conf" . fs_filehandler::NewLine();

		file_put_contents($dovecotConfigPath, $write, FILE_APPEND);
	}

	$write = "";
	$write .= "#Sentora TLS Config" . fs_filehandler::NewLine();
	$write .= "ssl = yes" . fs_filehandler::NewLine();
	$write .= "ssl_cert = <" . $dir . ctrl_options::GetSystemOption('sentora_domain') . ".crt" . fs_filehandler::NewLine();
	$write .= "ssl_key = <" . $dir . ctrl_options::GetSystemOption('sentora_domain') . ".key" . fs_filehandler::NewLine();
	$write .= "# Disable SSLV3 - Poodle" . fs_filehandler::NewLine();
	$write .= "ssl_protocols = !SSLv2 !SSLv3" . fs_filehandler::NewLine();
	$write .= "#Sentora TLS Config END" . fs_filehandler::NewLine();

	fs_filehandler::UpdateFile(dirname($dovecotConfigPath) . "/tls.conf", 0777, $write);
}

function WriteProFTPdConfig(){
	$domain = ctrl_options::GetSystemOption('sentora_domain');
	$dir = getSSLDir($domain, "");

	if(!is_dir($dir) || !file_exists($dir . $domain . ".key") || !file_exists($dir . $domain . ".crt")){
		return
	}

	if(is_dir($sentoraRoot . "configs/proftpd/")){
		$proftpdConfPath = ctrl_options::GetSystemOption("ftp_config_file");
		$proftpdTLSPath = dirname($proftpdConfPath) . "/tls.conf";

		if(file_exists($proftpdConfPath)){
			fs_filehandler::CopyFile($proftpdConfPath, $proftpdConfPath . "bak");
			$content = @file_get_contents($proftpdConfPath);

			if(stripos($content, "#Sentora TLS Config") === false){
				file_put_contents($proftpdConfPath, "#Sentora TLS Config" . fs_filehandler::NewLine() . "Include " . $proftpdTLSPath . fs_filehandler::NewLine(), FILE_APPEND);
			}

			$write = "";
			$write .= "<IfModule mod_dso.c>" . fs_filehandler::NewLine();
			$write .= "\tLoadModule mod_tls.c" . fs_filehandler::NewLine();
			$write .= "</IfModule>" . fs_filehandler::NewLine() . fs_filehandler::NewLine();
			$write .= "<IfModule mod_tls.c>" . fs_filehandler::NewLine();
			$write .= "\tTLSEngine                  on" . fs_filehandler::NewLine();
			$write .= "\tTLSRequired                off" . fs_filehandler::NewLine();
			$write .= "\tTLSVerifyClient            off" . fs_filehandler::NewLine();
			$write .= "\tTLSLog                     /var/log/proftpd/tls.log" . fs_filehandler::NewLine();
			$write .= "\tTLSProtocol                TLSv1" . fs_filehandler::NewLine();
			$write .= "\tTLSCipherSuite             HIGH:MEDIUM:+TLSv1:!SSLv2:!SSLv3" . fs_filehandler::NewLine();
			$write .= "\tTLSOptions                 NoCertRequest AllowClientRenegotiations NoSessionReuseRequired" . fs_filehandler::NewLine();
			$write .= "\tTLSRSACertificateFile      " . $dir . $domain . ".crt" . fs_filehandler::NewLine();
			$write .= "\tTLSRSACertificateKeyFile   " . $dir . $domain . ".key" . fs_filehandler::NewLine();
			$write .= "</IfModule>" . fs_filehandler::NewLine();

			fs_filehandler::UpdateFile($proftpdTLSPath, 0777, $write);
		}
	}
}

function WriteSSLConfig(){
	global $zdbh;

	$apache_dir = dirname(ctrl_options::GetSystemOption('apache_vhost'));
	$sentora_root = ctrl_options::GetSystemOption('sentora_root');
	$hosted_dir = ctrl_options::GetSystemOption("hosted_dir");

	$files = glob($apache_dir . "/users_ssl/*.conf");

	$global_vhost_pattern = "~##START-GVHOST-CONF##\s*(.*)##END-GVHOST-CONF##~misU";
	$custom_vhost_pattern = "~##START-CVHOST-CONF##\s*(.*)##END-CVHOST-CONF##~misU";

	echo fs_filehandler::NewLine() . "Deamon run from SSL_manager" . fs_filehandler::NewLine();

	foreach($files as $k => $v){
		//echo $v . fs_filehandler::NewLine();
		//file_put_contents("/etc/sentora/output.txt", $v, FILE_APPEND);

		$domain = basename($v, ".conf");
		$domaindata = array();

		$domain_ispanel = $domain == ctrl_options::GetSystemOption('sentora_domain');
		$rootdir = str_replace(".", "_", $domain);

		$vhostuser = array("username" => "");

		if($domain_ispanel){
			/*$sql = $zdbh->prepare("SELECT `ac_id_pk` FROM `x_accounts` WHERE `ac_deleted_ts` IS NULL AND `ac_group_fk`='1' LIMIT 1;");
			$sql->execute();

			$uid = $sql->fetch(PDO::FETCH_ASSOC);

			$vhostuser = ctrl_users::GetUserDetail($uid["ac_id_pk"]);*/
		}
		else{
			$sql = $zdbh->prepare("SELECT * FROM `x_vhosts` WHERE `vh_deleted_ts` IS NULL AND `vh_name_vc`=:vh_name LIMIT 1;");
			$sql->bindParam(":vh_name", $domain);
			$sql->execute();

			$domaindata = $sql->fetch(PDO::FETCH_ASSOC);

			if(empty($domaindata)){
				echo "Couldn't find the vhost entry for " . $domain . " removing SSL vhost.";
				unlink($apache_dir . "/users_ssl/" . $domain . ".conf");
				continue;
			}

			$vhostuser = ctrl_users::GetUserDetail($domaindata['vh_acc_fk']);
		}

		$ssl_dir = getSSLDir($domain, $vhostuser["username"]);

		$write = "<VirtualHost *:443>" . fs_filehandler::NewLine();
		$write .= "\tServerAdmin " . ($domain_ispanel ? ctrl_options::GetSystemOption('email_from_address') : $vhostuser["email"]) . fs_filehandler::NewLine();
		$write .= "\tServerName $domain" . fs_filehandler::NewLine();
		$write .= "ServerAlias www." . $domain . fs_filehandler::NewLine();

		$webdir = $domain_ispanel ? $sentora_root : "$hosted_dir$vhostuser[username]/public_html/$rootdir";

		if($domain_ispanel) {
			$write .= "\tDocumentRoot " . ctrl_options::GetSystemOption('sentora_root') . fs_filehandler::NewLine();
		} else {
			$write .= "\tDocumentRoot $webdir/" . fs_filehandler::NewLine();
		}

		//$hosted_dir$vhostuser[ac_user_vc]/ssl/$rootdir
		$write .= "\tSSLEngine on" . fs_filehandler::NewLine();
		$write .= "\tSSLCertificateFile $ssl_dir$domain.crt" . fs_filehandler::NewLine();
		$write .= "\tSSLCertificateKeyFile $ssl_dir$domain.key" . fs_filehandler::NewLine();
		if(file_exists("$ssl_dir/intermediate.crt")){
			$write .= "\tSSLCACertificateFile $ssl_dir/intermediate.crt" . fs_filehandler::NewLine();
		}

		if ((double) sys_versions::ShowApacheVersion() > 2.2) {
			$write .= "\tSSLProtocol ALL -SSLv2 -SSLv3" . fs_filehandler::NewLine();
		}
		else{
			$write .= "\tSSLProtocol TLSv1" . fs_filehandler::NewLine();
		}
		$write .= "\tSSLHonorCipherOrder on" . fs_filehandler::NewLine();
		$write .= "\tSSLCipherSuite \"EECDH+ECDSA+AESGCM EECDH+aRSA+AESGCM EECDH+ECDSA+SHA384 EECDH+ECDSA+SHA256 EECDH+aRSA+SHA384 EECDH+aRSA+SHA256 EECDH+aRSA+RC4 EECDH EDH+aRSA RC4 !aNULL !eNULL !LOW !3DES !MD5 !EXP !PSK !SRP !DSS !RC4\"" . fs_filehandler::NewLine();
		$write .= "\tAddOutputFilterByType DEFLATE text/html text/plain text/xml text/css text/javascript application/javascript" . fs_filehandler::NewLine();


		if($domain_ispanel) {
			$write .= 'ErrorLog "' . ctrl_options::GetSystemOption('log_dir') . 'sentora-error.log" ' . fs_filehandler::NewLine();
			$write .= 'CustomLog "' . ctrl_options::GetSystemOption('log_dir') . 'sentora-access.log" ' . ctrl_options::GetSystemOption('access_log_format') . fs_filehandler::NewLine();
			$write .= 'CustomLog "' . ctrl_options::GetSystemOption('log_dir') . 'sentora-bandwidth.log" ' . ctrl_options::GetSystemOption('bandwidth_log_format') . fs_filehandler::NewLine();
			$write .= "AddType application/x-httpd-php .php" . fs_filehandler::NewLine();

		} else {
			if (ctrl_options::GetSystemOption('use_openbase') == "true") {
                if ($domaindata['vh_obasedir_in'] <> 0) {
                    $write .= 'php_admin_value open_basedir "' . ctrl_options::GetSystemOption('hosted_dir') . $vhostuser['username'] . "/public_html" . $domaindata['vh_directory_vc'] . ctrl_options::GetSystemOption('openbase_seperator') . ctrl_options::GetSystemOption('openbase_temp') . '"' . fs_filehandler::NewLine();
                }
            }
            if (ctrl_options::GetSystemOption('use_suhosin') == "true") {
                if ($domaindata['vh_suhosin_in'] <> 0) {
                    $write .= ctrl_options::GetSystemOption('suhosin_value') . fs_filehandler::NewLine();
                }
            }
            // Logs
            if (!is_dir(ctrl_options::GetSystemOption('log_dir') . "domains/" . $vhostuser['username'] . "/")) {
                fs_director::CreateDirectory(ctrl_options::GetSystemOption('log_dir') . "domains/" . $vhostuser['username'] . "/");
            }
            $write .= 'ErrorLog "' . ctrl_options::GetSystemOption('log_dir') . "domains/" . $vhostuser['username'] . "/" . $domaindata['vh_name_vc'] . '-error.log" ' . fs_filehandler::NewLine();
            $write .= 'CustomLog "' . ctrl_options::GetSystemOption('log_dir') . "domains/" . $vhostuser['username'] . "/" . $domaindata['vh_name_vc'] . '-access.log" ' . ctrl_options::GetSystemOption('access_log_format') . fs_filehandler::NewLine();
            $write .= 'CustomLog "' . ctrl_options::GetSystemOption('log_dir') . "domains/" . $vhostuser['username'] . "/" . $domaindata['vh_name_vc'] . '-bandwidth.log" ' . ctrl_options::GetSystemOption('bandwidth_log_format') . fs_filehandler::NewLine();
		}

		$write .= "\t<Directory '$webdir'>" . fs_filehandler::NewLine();
		$write .= "\t\tOptions +FollowSymLinks -Indexes" . fs_filehandler::NewLine();
		$write .= "\t\tAllowOverride All" . fs_filehandler::NewLine();
		$write .= "\t\tRequire all granted" . fs_filehandler::NewLine();
		$write .= "\t</Directory>" . fs_filehandler::NewLine() . fs_filehandler::NewLine();

		// Global VHhost config
		$write .= "##START-GVHOST-CONF##" . fs_filehandler::NewLine();
		$write .= ctrl_options::GetSystemOption('global_vhcustom') . fs_filehandler::NewLine();
		$write .= "##END-GVHOST-CONF##" . fs_filehandler::NewLine() . fs_filehandler::NewLine();

		// Client/Panel VHost config
		$write .= "##START-CVHOST-CONF##" . fs_filehandler::NewLine();

		if($domain_ispanel){
			$write .= ctrl_options::GetSystemOption('global_zpcustom');
		}
		else{
			$write .= $domaindata["vh_custom_tx"];
		}

		$write .= "##END-CVHOST-CONF##" . fs_filehandler::NewLine() . fs_filehandler::NewLine();

		$write .= "</VirtualHost>" . fs_filehandler::NewLine();

		file_put_contents($v, $write);

		$RewriteCond = fs_filehandler::NewLine() . '#Sentora HTTPS Redirect' . fs_filehandler::NewLine() . 'RewriteCond %{HTTPS} off' . fs_filehandler::NewLine() . 'RewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI}' . fs_filehandler::NewLine();

		if((file_exists($webdir . "/.htaccess") && stripos(file_get_contents($webdir . "/.htaccess"), "#Sentora HTTPS Redirect") === false) || !file_exists($webdir . "/.htaccess")){
			file_put_contents($webdir . "/.htaccess", $RewriteCond, FILE_APPEND);
		}

		echo "Updated SSL vhost for " . $domain . fs_filehandler::NewLine();
	}
}

?>
