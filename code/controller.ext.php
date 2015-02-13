<?php

class module_controller extends ctrl_module
{
		
		static $ok;
		static $error;
		static $delok;
		static $keyadd;
		static $download;
		static $empty;
		
    /**
     * The 'worker' methods.
     */
	 static function ExecuteDelete($domain, $username)
	 {
		 global $zdbh;
		 global $controller;
		 $domain1 = str_replace('.', '_', $domain);
		 $dir = ctrl_options::GetSystemOption('hosted_dir') . $username ."/ssl/". $domain1;
		 $objects = scandir($dir);
     foreach ($objects as $object) {
       if ($object != "." && $object != "..") {
         unlink($dir."/".$object);
       }
     }
     reset($objects);
     rmdir($dir);
	 unlink("/etc/sentora/panel/users_ssl/" . $domain . ".conf");
	
		 return true;
		 	self::$delok = true;
	 }
	 
	 static function ExecuteCSR($domain, $name, $address, $city, $country, $company, $password)
	{
		global $zdbh;
		global $controller;
		$currentuser = ctrl_users::GetUserDetail();
		$formvars = $controller->GetAllControllerRequests('FORM');
		$config = array('private_key_bits' => 4096);
		if (!is_dir("/var/sentora/hostdata/". $currentuser["username"] ."/key/") ) {
				mkdir("/var/sentora/hostdata/". $currentuser["username"] ."/key/", 0777);
			}
		$dn = array(
								"countryName" => "$country",
								"stateOrProvinceName" => "$name",
								"localityName" => "$city",
								"organizationName" => "$company",
								"commonName" => "$domain",
								"emailAddress" => "$address"
							);
		
		$privkey = openssl_pkey_new($config);
		$csr = openssl_csr_new($dn, $privkey);
		
		openssl_csr_export($csr, $csrout);
		openssl_pkey_export($privkey, $pkeyout, $password);
		
		openssl_pkey_export_to_file($privkey, "/var/sentora/hostdata/". $currentuser["username"] ."/key/".$domain.".key");
		
		$email = $address;
			$emailsubject = "Certificate Signing Request";
            $emailbody = "Hi $currentuser[username]\n\n
			---------------------------------CSR-------------------------------\n\n\n
			$csrout
			\n\n\n
			---------------------------------CSR END-------------------------------";
		

            $phpmailer = new sys_email();
            $phpmailer->Subject = $emailsubject;
            $phpmailer->Body = $emailbody;
			$phpmailer->AddAttachment("/var/sentora/hostdata/". $currentuser["username"] ."/key/".$domain.".key");
            $phpmailer->AddAddress($email);
            $phpmailer->SendEmail();
			unlink("/var/sentora/hostdata/". $currentuser["username"] ."/key/".$domain.".key");
			rmdir("/var/sentora/hostdata/". $currentuser["username"] ."/key/");
			self::$keyadd = true;
			return true;
	}
	
	 static function ExecuteDownload($domain, $username)
	 {
		set_time_limit(0);
		global $zdbh;
		global $controller;
		$domain = str_replace('.', '_', $domain);
		$temp_dir = ctrl_options::GetSystemOption('sentora_root') . "etc/tmp/";
		$homedir = ctrl_options::GetSystemOption('hosted_dir') . $username;
    	$backupname = $domain;
		$resault = exec("cd " . $homedir . "/ssl/" .$domain ."/ && " . ctrl_options::GetSystemOption('zip_exe') . " -r9 " . $temp_dir . $backupname . " *");
        @chmod($temp_dir . $backupname . ".zip", 0777);
		$filename = $backupname . ".zip";
		$filepath = $temp_dir;
		header("Pragma: public");
		header("Expires: 0");
		header("Cache-Control: must-revalidate, post-check=0, pre-check=0");
		header("Cache-Control: public");
		header("Content-Description: File Transfer");
		header("Content-type: application/octet-stream");
		header("Content-Disposition: attachment; filename=\"".$filename."\"");
		header("Content-Transfer-Encoding: binary");
		header("Content-Length: ".filesize($filepath.$filename));
		ob_end_flush();
		readfile($filepath.$filename);
		unlink($temp_dir . $backupname . ".zip");
		return true;
		}
		
		static function ExecuteCustomSSL($domain, $path, $name, $address, $city, $country, $company)
		{
			global $zdbh;
		global $controller;
		$currentuser = ctrl_users::GetUserDetail();
		$formvars = $controller->GetAllControllerRequests('FORM');
		$rootdir = str_replace('.', '_', $domain);
		
		if (!is_dir("/var/sentora/hostdata/". $currentuser["username"] ."/ssl/") ) {
				mkdir("/var/sentora/hostdata/". $currentuser["username"] ."/ssl/", 0777);
			}
		if (!is_dir("/var/sentora/hostdata/". $currentuser["username"] ."/ssl/". $rootdir ."/") ) {
				mkdir("/var/sentora/hostdata/". $currentuser["username"] ."/ssl/". $rootdir ."/", 0777);
			} else {
			self::$error = true;
			return false;
			}
			// GET user info
		
		 $dn = array(
								"countryName" => "$country",
								"stateOrProvinceName" => "$name",
								"localityName" => "$city",
								"organizationName" => "$company",
								"commonName" => "$domain",
								"emailAddress" => "$address"
							); 		
		// Make Key
		
		//$config = array('private_key_bits' => 4096);
		
		$privkey = openssl_pkey_new();
		
		// Generate a certificate signing request
		$csr = openssl_csr_new($dn, $privkey);
		
		$config = array("digest_alg" => "sha256");
		
		$sscert = openssl_csr_sign($csr, null, $privkey, 365, $config);
		
		//openssl_csr_export($csr, $csrout);
		//openssl_x509_export($sscert, $certout);
		//openssl_pkey_export($privkey, $pkeyout, $password);
		
		openssl_x509_export_to_file($sscert, "/var/sentora/hostdata/". $currentuser["username"] ."/ssl/" .$rootdir ."/". $domain .".crt");
		openssl_pkey_export_to_file($privkey, "/var/sentora/hostdata/". $currentuser["username"] ."/ssl/" .$rootdir ."/". $domain .".key");
		
			// now write the contents to the file
			$handle = fopen("/etc/sentora/panel/users_ssl/" . $domain . ".conf", "w+");
			$write = "<VirtualHost *:443>\n";
			fwrite($handle, $write);
			$write = "ServerAdmin $address\n";
			fwrite($handle, $write);
			$write = "ServerName $domain\n";
			fwrite($handle, $write);
			$write = "DocumentRoot $path\n";
			fwrite($handle, $write);
			$write = "SSLEngine on\n";
			fwrite($handle, $write);
			$write = "SSLCertificateFile /var/sentora/hostdata/$currentuser[username]/ssl/$rootdir/$domain.crt\n";
			fwrite($handle, $write);
			$write = "SSLCertificateKeyFile /var/sentora/hostdata/$currentuser[username]/ssl/$rootdir/$domain.key\n";
			fwrite($handle, $write);
			$write = "SSLProtocol -All +TLSv1 +TLSv1.1 +TLSv1.2\n";
			fwrite($handle, $write);
			$write = "SSLCipherSuite ECDHE-RSA-AES256-SHA384:AES256-SHA256:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM;\n";
			fwrite($handle, $write);
			$write = "<Directory '$path'>\n";
			fwrite($handle, $write);
			$write = "Options +FollowSymLinks -Indexes\n";
			fwrite($handle, $write);
			$write = "AllowOverride All\n";
			fwrite($handle, $write);
			$write = "Require all granted\n";
			fwrite($handle, $write);
			$write = "</Directory>\n";
			fwrite($handle, $write);
			$write = "</VirtualHost>\n";
			fwrite($handle, $write);
			fclose($handle);			
			// now finish
			// tell apcahe to reload as soon as possible
			self::SetWriteApacheConfigTrue();
	self::$ok = true;	
	return true;
		}
		
	 static function ExecuteMakessl($domain, $name, $address, $city, $country, $company)
    {
		global $zdbh;
		global $controller;
		$currentuser = ctrl_users::GetUserDetail();
		$formvars = $controller->GetAllControllerRequests('FORM');
		$rootdir = str_replace('.', '_', $domain);
		
		if (!is_dir("/var/sentora/hostdata/". $currentuser["username"] ."/ssl/") ) {
				mkdir("/var/sentora/hostdata/". $currentuser["username"] ."/ssl/", 0777);
			}
		if (!is_dir("/var/sentora/hostdata/". $currentuser["username"] ."/ssl/". $rootdir ."/") ) {
				mkdir("/var/sentora/hostdata/". $currentuser["username"] ."/ssl/". $rootdir ."/", 0777);
			} else {
			self::$error = true;
			return false;
			}
	
	// GET user info
		
		 $dn = array(
								"countryName" => "$country",
								"stateOrProvinceName" => "$name",
								"localityName" => "$city",
								"organizationName" => "$company",
								"commonName" => "$domain",
								"emailAddress" => "$address"
							); 		
		// Make Key
		
		//$config = array('private_key_bits' => 4096);
		
		$privkey = openssl_pkey_new();
		
		// Generate a certificate signing request
		$csr = openssl_csr_new($dn, $privkey);
		
		$config = array("digest_alg" => "sha256");
		
		$sscert = openssl_csr_sign($csr, null, $privkey, 365, $config);
		
		//openssl_csr_export($csr, $csrout);
		//openssl_x509_export($sscert, $certout);
		//openssl_pkey_export($privkey, $pkeyout, $password);
		
		openssl_x509_export_to_file($sscert, "/var/sentora/hostdata/". $currentuser["username"] ."/ssl/" .$rootdir ."/". $domain .".crt");
		openssl_pkey_export_to_file($privkey, "/var/sentora/hostdata/". $currentuser["username"] ."/ssl/" .$rootdir ."/". $domain .".key");
		
			// now write the contents to the file
			$handle = fopen("/etc/sentora/panel/users_ssl/" . $domain . ".conf", "w+");
			$write = "<VirtualHost *:443>\n";
			fwrite($handle, $write);
			$write = "ServerAdmin $address\n";
			fwrite($handle, $write);
			$write = "ServerName $domain\n";
			fwrite($handle, $write);
			if($domain == ctrl_options::GetSystemOption('sentora_domain')) { 
			$write = "DocumentRoot /etc/sentora/panel/\n";
			} else {
			$write = "DocumentRoot /var/sentora/hostdata/$currentuser[username]/public_html/$rootdir/\n";
			}
			fwrite($handle, $write);
			$write = "SSLEngine on\n";
			fwrite($handle, $write);
			$write = "SSLCertificateFile /var/sentora/hostdata/$currentuser[username]/ssl/$rootdir/$domain.crt\n";
			fwrite($handle, $write);
			$write = "SSLCertificateKeyFile /var/sentora/hostdata/$currentuser[username]/ssl/$rootdir/$domain.key\n";
			fwrite($handle, $write);
			$write = "SSLProtocol -All +TLSv1 +TLSv1.1 +TLSv1.2\n";
			fwrite($handle, $write);
			$write = "SSLCipherSuite ECDHE-RSA-AES256-SHA384:AES256-SHA256:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM;\n";
			fwrite($handle, $write);
			if($domain == ctrl_options::GetSystemOption('sentora_domain')) { 
			$write = "<Directory '/etc/sentora/panel/'>\n";
			} else {
			$write = "<Directory '/var/sentora/hostdata/$currentuser[username]/public_html/$rootdir/'>\n";
			}
			fwrite($handle, $write);
			$write = "Options +FollowSymLinks -Indexes\n";
			fwrite($handle, $write);
			$write = "AllowOverride All\n";
			fwrite($handle, $write);
			$write = "Require all granted\n";
			fwrite($handle, $write);
			$write = "</Directory>\n";
			fwrite($handle, $write);
			$write = "</VirtualHost>\n";
			fwrite($handle, $write);
			fclose($handle);			
			// now finish
			// tell apcahe to reload as soon as possible
			self::SetWriteApacheConfigTrue();
	self::$ok = true;	
	return true;	
	}
	
	static function SetWriteApacheConfigTrue() {
        global $zdbh;
        $sql = $zdbh->prepare("UPDATE x_settings
								SET so_value_tx='true'
								WHERE so_name_vc='apache_changed'");
        $sql->execute();
    }
	
	static function ListDomains($uid)
    {
        global $zdbh;
		global $controller;
        $currentuser = ctrl_users::GetUserDetail($uid);
        $sql = "SELECT * FROM x_vhosts WHERE vh_acc_fk=:userid AND vh_enabled_in=1 AND vh_deleted_ts IS NULL ORDER BY vh_name_vc ASC";
        $numrows = $zdbh->prepare($sql);
        $numrows->bindParam(':userid', $currentuser['userid']);
        $numrows->execute();
        if ($numrows->fetchColumn() <> 0) {
            $sql = $zdbh->prepare($sql);
            $sql->bindParam(':userid', $currentuser['userid']);
            $res = array();
            $sql->execute();
			if($currentuser["username"] == "zadmin") {
					$name = ctrl_options::GetSystemOption('sentora_domain');
				$res[] = array('domain' => "$name");
				}
            while ($rowdomains = $sql->fetch()) {
                $res[] = array('domain' => $rowdomains['vh_name_vc']);
            }
            return $res;
        } else {
            return false;
        }
    }
	
	 static function ListSSL($uname)
	{
	    global $zdbh;
		global $controller;
		if (!is_dir("/var/sentora/hostdata/". $uname ."/ssl/") ) {
				mkdir("/var/sentora/hostdata/". $uname ."/ssl/", 0777);
			}
		$dir = "/var/sentora/hostdata/$uname/ssl/";
		if(substr($dir, -1) != "/") $dir .= "/";
		$d = @dir($dir);
    	while(false !== ($entry = $d->read())) {
			$entry1 = str_replace('_', '.', $entry);
			if($entry[0] == ".") continue;
			$retval[] = array("name" => "$entry1");
}
    $d->close();

    return $retval;
  }
		
	/**
     * End 'worker' methods.
     */

    /**
     * Webinterface sudo methods.
     */ 
	
	static function doUploadSSL()
	{
		global $zdbh;
		global $controller;
		$currentuser = ctrl_users::GetUserDetail();
		$formvars = $controller->GetAllControllerRequests('FORM');
		$domain = $formvars["inDomain"];
		$rootdir = str_replace('.', '_', $domain);
		if (empty($_FILES["inkey"]["name"]) || empty($_FILES["inWCA"]["name"])) { 
		self::$empty = true;
		return false; }
		if (!is_dir("/var/sentora/hostdata/". $currentuser["username"] ."/ssl/") ) {
				mkdir("/var/sentora/hostdata/". $currentuser["username"] ."/ssl/", 0777);
			}
		if (!is_dir("/var/sentora/hostdata/". $currentuser["username"] ."/ssl/". $rootdir ."/") ) {
				mkdir("/var/sentora/hostdata/". $currentuser["username"] ."/ssl/". $rootdir ."/", 0777);
			} else {
			self::$error = true;
			return false;
			}
			
			$target_dir = "/var/sentora/hostdata/". $currentuser["username"] ."/ssl/". $rootdir ."/";
			
			$uploadkey = $target_dir . $domain . ".key";
			$uploadwcrt = $target_dir . $domain . ".crt";
			$uploadicrt = $target_dir . "intermediate.crt";
			move_uploaded_file($_FILES["inkey"]["tmp_name"], $uploadkey);
			move_uploaded_file($_FILES["inWCA"]["tmp_name"], $uploadwcrt);
			move_uploaded_file($_FILES["inICA"]["tmp_name"], $uploadicrt);
			
			$handle = fopen("/etc/sentora/panel/users_ssl/" . $domain . ".conf", "w+");
			$write = "<VirtualHost *:443>\n";
			fwrite($handle, $write);
			$write = "ServerAdmin $currentuser[email]\n";
			fwrite($handle, $write);
			$write = "ServerName $domain\n";
			fwrite($handle, $write);
			if($domain == ctrl_options::GetSystemOption('sentora_domain')) { 
			$write = "DocumentRoot /etc/sentora/panel/\n";
			} else {
			$write = "DocumentRoot /var/sentora/hostdata/$currentuser[username]/public_html/$rootdir/\n";
			}
			fwrite($handle, $write);
			$write = "SSLEngine on\n";
			fwrite($handle, $write);
			$write = "SSLCertificateFile /var/sentora/hostdata/$currentuser[username]/ssl/$rootdir/$domain.crt\n";
			fwrite($handle, $write);
			$write = "SSLCertificateKeyFile /var/sentora/hostdata/$currentuser[username]/ssl/$rootdir/$domain.key\n";
			fwrite($handle, $write);
			$write = "SSLCACertificateFile /var/sentora/hostdata/$currentuser[username]/ssl/$rootdir/intermediate.crt\n";
			fwrite($handle, $write);
			$write = "SSLProtocol -All +TLSv1 +TLSv1.1 +TLSv1.2\n";
			fwrite($handle, $write);
			$write = "SSLCipherSuite ECDHE-RSA-AES256-SHA384:AES256-SHA256:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM;\n";
			fwrite($handle, $write);
			if($domain == ctrl_options::GetSystemOption('sentora_domain')) { 
			$write = "<Directory '/etc/sentora/panel/'>\n";
			} else {
			$write = "<Directory '/var/sentora/hostdata/$currentuser[username]/public_html/$rootdir/'>\n";
			}
			fwrite($handle, $write);
			$write = "Options +FollowSymLinks -Indexes\n";
			fwrite($handle, $write);
			$write = "AllowOverride All\n";
			fwrite($handle, $write);
			$write = "Require all granted\n";
			fwrite($handle, $write);
			$write = "</Directory>\n";
			fwrite($handle, $write);
			$write = "</VirtualHost>\n";
			fwrite($handle, $write);
			fclose($handle);			
			// now finish
			// tell apcahe to reload as soon as possible
			self::SetWriteApacheConfigTrue();
			self::$ok = true;
		return true;
	}
	
	static function doselect()
    {
        global $controller;
        runtime_csfr::Protect();
        $currentuser = ctrl_users::GetUserDetail();
        $formvars = $controller->GetAllControllerRequests('FORM');
		
            if (isset($formvars['inSSLself'])) {
                header("location: ./?module=" . $controller->GetCurrentModule() . '&show=ShowSelf');
                exit;
            }
			if (isset($formvars['inSSLbought'])) {
                header("location: ./?module=" . $controller->GetCurrentModule() . '&show=Bought');
                exit;
            }
			if (isset($formvars['inSSLCSR'])) {
                header("location: ./?module=" . $controller->GetCurrentModule() . '&show=ShowCSR');
                exit;
            }
			if (isset($formvars['inSSLCustom'])) {
                header("location: ./?module=" . $controller->GetCurrentModule() . '&show=ShowCustom');
                exit;
            }
        return true;
    }
	 static function doEdit()
    {
        global $controller;
        $currentuser = ctrl_users::GetUserDetail();
        $formvars = $controller->GetAllControllerRequests('FORM');
        if (self::ExecuteDownload($formvars['inName'], $currentuser["username"]))
        return true;
    }
	
	static function doDelete()
    {
        global $controller;
        runtime_csfr::Protect();
        $currentuser = ctrl_users::GetUserDetail();
        $formvars = $controller->GetAllControllerRequests('FORM');
        if (self::ExecuteDelete($formvars['inName'], $currentuser["username"]))
        return true;
    }
	 static function doMakeCSR()
    {
        global $controller;
        runtime_csfr::Protect();
        $currentuser = ctrl_users::GetUserDetail();
        $formvars = $controller->GetAllControllerRequests('FORM');
		if (empty($formvars['inDomain']) || empty($formvars['inName']) || empty($formvars['inAddress']) || empty($formvars['inCity']) || empty($formvars['inCountry']) || empty($formvars['inCompany'])) { 
		self::$empty = true;
		return false; }
        if (self::ExecuteCSR($formvars['inDomain'], $formvars['inName'], $formvars['inAddress'], $formvars['inCity'], $formvars['inCountry'], $formvars['inCompany'], $formvars['inPassword']))
        return true;
    }
	 
	 
	
	static function getListCountry()
	{
		$res = '<option value="AX"> Aland Islands </option><option value="AD"> Andorra </option><option value="AE"> United Arab Emirates </option>option value="AF"> Afghanistan </option><option value="AG"> Antigua and Barbuda </option><option value="AI"> Anguilla </option><option value="AL"> Albania </option><option value="AM"> Armenia </option><option value="AN"> Netherlands Antilles </option><option value="AO"> Angola </option><option value="AQ"> Antarctica </option><option value="AR"> Argentina </option><option value="AS"> American Samoa </option><option value="AT"> Austria </option><option value="AU"> Australia </option><option value="AW"> Aruba </option><option value="AZ"> Azerbaijan </option><option value="BA"> Bosnia and Herzegovina </option><option value="BB"> Barbados </option><option value="BD"> Bangladesh </option><option value="BE"> Belgium </option><option value="BF"> Burkina Faso </option><option value="BG"> Bulgaria </option><option value="BH"> Bahrain </option><option value="BI"> Burundi </option><option value="BJ"> Benin </option><option value="BM"> Bermuda </option><option value="BN"> Brunei Darussalam </option><option value="BO"> Bolivia </option><option value="BR"> Brazil </option><option value="BS"> Bahamas </option><option value="BT"> Bhutan </option><option value="BV"> Bouvet Island </option><option value="BW"> Botswana </option><option value="BZ"> Belize </option><option value="CA"> Canada </option><option value="CC"> Cocos (Keeling) Islands </option><option value="CF"> Central African Republic </option><option value="CH"> Switzerland </option><option value="CI"> Cote D\'Ivoire (Ivory Coast) </option><option value="CK"> Cook Islands </option><option value="CL"> Chile </option><option value="CM"> Cameroon </option><option value="CN"> China </option><option value="CO"> Colombia </option><option value="CR"> Costa Rica </option><option value="CS"> Czechoslovakia (former) </option><option value="CV"> Cape Verde </option><option value="CX"> Christmas Island </option><option value="CY"> Cyprus </option><option value="CZ"> Czech Republic </option><option value="DE"> Germany </option><option value="DJ"> Djibouti </option><option value="DK"> Denmark </option><option value="DM"> Dominica </option><option value="DO"> Dominican Republic </option><option value="DZ"> Algeria </option><option value="EC"> Ecuador </option><option value="EE"> Estonia </option><option value="EG"> Egypt </option><option value="EH"> Western Sahara </option><option value="ER"> Eritrea </option><option value="ES"> Spain </option><option value="ET"> Ethiopia </option><option value="FI"> Finland </option><option value="FJ"> Fiji </option><option value="FK"> Falkland Islands (Malvinas) </option><option value="FM"> Micronesia </option><option value="FO"> Faroe Islands </option><option value="FR"> France </option><option value="FX"> France, Metropolitan </option><option value="GA"> Gabon </option><option value="GB"> Great Britain (UK) </option><option value="GD"> Grenada </option><option value="GE"> Georgia </option><option value="GF"> French Guiana </option><option value="GG"> Guernsey </option><option value="GH"> Ghana </option><option value="GI"> Gibraltar </option><option value="GL"> Greenland </option><option value="GM"> Gambia </option><option value="GN"> Guinea </option><option value="GP"> Guadeloupe </option><option value="GQ"> Equatorial Guinea </option><option value="GR"> Greece </option><option value="GS"> S. Georgia and S. Sandwich Isls. </option><option value="GT"> Guatemala </option><option value="GU"> Guam </option><option value="GW"> Guinea-Bissau </option><option value="GY"> Guyana </option><option value="HK"> Hong Kong </option><option value="HM"> Heard and McDonald Islands </option><option value="HN"> Honduras </option><option value="HR"> Croatia (Hrvatska) </option><option value="HT"> Haiti </option><option value="HU"> Hungary </option><option value="ID"> Indonesia </option><option value="IE">Ireland </option><option value="IL"> Israel </option><option value="IM"> Isle of Man </option><option value="IN"> India </option><option value="IO"> British Indian Ocean Territory </option><option value="IS"> Iceland </option><option value="IT"> Italy </option><option value="JE"> Jersey </option><option value="JM"> Jamaica </option><option value="JO"> Jordan </option><option value="JP"> Japan </option><option value="KE"> Kenya </option><option value="KG"> Kyrgyzstan </option><option value="KH"> Cambodia </option><option value="KI"> Kiribati </option><option value="KM"> Comoros </option><option value="KN"> Saint Kitts and Nevis </option><option value="KR"> Korea (South) </option><option value="KW"> Kuwait </option><option value="KY"> Cayman Islands </option><option value="KZ"> Kazakhstan </option><option value="LA"> Laos </option><option value="LC"> Saint Lucia </option><option value="LI"> Liechtenstein </option><option value="LK"> Sri Lanka </option><option value="LS"> Lesotho </option><option value="LT"> Lithuania </option><option value="LU"> Luxembourg </option><option value="LV"> Latvia </option><option value="LY"> Libya </option><option value="MA"> Morocco </option><option value="MC"> Monaco </option><option value="MD"> Moldova </option><option value="ME"> Montenegro </option><option value="MG"> Madagascar </option><option value="MH"> Marshall Islands </option><option value="MK"> Macedonia </option><option value="ML"> Mali </option><option value="MM"> Myanmar </option><option value="MN"> Mongolia </option><option value="MO"> Macau </option><option value="MP"> Northern Mariana Islands </option><option value="MQ"> Martinique </option><option value="MR"> Mauritania </option><option value="MS"> Montserrat </option><option value="MT"> Malta </option><option value="MU"> Mauritius </option><option value="MV"> Maldives </option><option value="MW"> Malawi </option><option value="MX"> Mexico </option><option value="MY"> Malaysia </option><option value="MZ"> Mozambique </option><option value="NA"> Namibia </option><option value="NC"> New Caledonia </option><option value="NE"> Niger </option><option value="NF"> Norfolk Island </option><option value="NG"> Nigeria </option><option value="NI"> Nicaragua </option><option value="NL"> Netherlands </option><option value="NO"> Norway </option><option value="NP"> Nepal </option><option value="NR"> Nauru </option><option value="NT"> Neutral Zone </option><option value="NU"> Niue </option><option value="NZ"> New Zealand (Aotearoa) </option><option value="OM"> Oman </option><option value="PA"> Panama </option><option value="PE"> Peru </option><option value="PF"> French Polynesia </option><option value="PG">Papua New Guinea </option><option value="PH"> Philippines </option><option value="PK"> Pakistan </option><option value="PL"> Poland </option><option value="PM"> St. Pierre and Miquelon </option><option value="PN"> Pitcairn </option><option value="PR"> Puerto Rico </option><option value="PS"> Palestinian Territory </option><option value="PT"> Portugal </option><option value="PW"> Palau </option><option value="PY"> Paraguay </option><option value="QA"> Qatar </option><option value="RE"> Reunion </option><option value="RO"> Romania </option><option value="RS"> Serbia </option><option value="RU"> Russian Federation </option><option value="RW"> Rwanda </option><option value="SA"> Saudi Arabia </option><option value="SB"> Solomon Islands </option><option value="SC"> Seychelles </option><option value="SE"> Sweden </option><option value="SG"> Singapore </option><option value="SH"> St. Helena </option><option value="SI"> Slovenia </option><option value="SJ"> Svalbard and Jan Mayen Islands </option><option value="SK"> Slovak Republic </option><option value="SL"> Sierra Leone </option><option value="SM"> San Marino </option><option value="SN"> Senegal </option><option value="SR"> Suriname </option><option value="ST"> Sao Tome and Principe </option><option value="SU"> USSR (former) </option><option value="SV"> El Salvador </option><option value="SZ"> Swaziland </option><option value="TC"> Turks and Caicos Islands </option><option value="TD"> Chad </option><option value="TF"> French Southern Territories </option><option value="TG"> Togo </option><option value="TH"> Thailand </option><option value="TJ"> Tajikistan </option><option value="TK"> Tokelau </option><option value="TM"> Turkmenistan </option><option value="TN"> Tunisia </option><option value="TO"> Tonga </option><option value="TP"> East Timor </option><option value="TR"> Turkey </option><option value="TT"> Trinidad and Tobago </option><option value="TV"> Tuvalu </option><option value="TW"> Taiwan </option><option value="TZ"> Tanzania </option><option value="UA"> Ukraine </option><option value="UG"> Uganda </option><option value="UM"> US Minor Outlying Islands </option><option value="US"> United States </option><option value="UY"> Uruguay </option><option value="UZ"> Uzbekistan </option><option value="VA"> Vatican City State (Holy See) </option><option value="VC"> Saint Vincent and the Grenadines </option><option value="VE"> Venezuela </option><option value="VG"> Virgin Islands (British) </option><option value="VI"> Virgin Islands (U.S.) </option><option value="VN"> Viet Nam </option><option value="VU"> Vanuatu </option><option value="WF"> Wallis and Futuna Islands </option><option value="WS"> Samoa </option><option value="YE"> Yemen </option><option value="YT"> Mayotte </option><option value="ZA"> South Africa </option><option value="ZM"> Zambia </option>';
		return $res;
	}


	 static function doMakenew()
    {
        global $controller;
        runtime_csfr::Protect();
        $currentuser = ctrl_users::GetUserDetail();
        $formvars = $controller->GetAllControllerRequests('FORM');
		if (empty($formvars['inDomain']) || empty($formvars['inName']) || empty($formvars['inAddress']) || empty($formvars['inCity']) || empty($formvars['inCountry']) || empty($formvars['inCompany'])) { 
		self::$empty = true;
		return false; }
        if (self::ExecuteMakessl($formvars['inDomain'], $formvars['inName'], $formvars['inAddress'], $formvars['inCity'], $formvars['inCountry'], $formvars['inCompany']))
        return true;
    }
	 static function doAddCustum()
    {
        global $controller;
        runtime_csfr::Protect();
        $currentuser = ctrl_users::GetUserDetail();
        $formvars = $controller->GetAllControllerRequests('FORM');
		if (empty($formvars['inDomain']) || empty($formvars['inName']) || empty($formvars['inAddress']) || empty($formvars['inCity']) || empty($formvars['inCountry']) || empty($formvars['inCompany'])) { 
		self::$empty = true;
		return false; }
        if (self::ExecuteCustomSSL($formvars['inDomain'], $formvars['inPath'] ,$formvars['inName'], $formvars['inAddress'], $formvars['inCity'], $formvars['inCountry'], $formvars['inCompany']))
        return true;
    }
	 static function getDomainList()
    {
        $currentuser = ctrl_users::GetUserDetail();
        return self::ListDomains($currentuser['userid']);
    }
	
	static function getisShowCSR()
    {
        global $controller;
        $urlvars = $controller->GetAllControllerRequests('URL');
        return (isset($urlvars['show'])) && ($urlvars['show'] == "ShowCSR");
    }
	static function getisShowSelf()
    {
        global $controller;
        $urlvars = $controller->GetAllControllerRequests('URL');
        return (isset($urlvars['show'])) && ($urlvars['show'] == "ShowSelf");
    }
	
	static function getisShowCustom()
    {
        global $controller;
        $urlvars = $controller->GetAllControllerRequests('URL');
        return (isset($urlvars['show'])) && ($urlvars['show'] == "ShowCustom");
    }
	
	static function getisBought()
    {
        global $controller;
        $urlvars = $controller->GetAllControllerRequests('URL');
        return (isset($urlvars['show'])) && ($urlvars['show'] == "Bought");
    }
	
	static function getSSLList()
    {
        $currentuser = ctrl_users::GetUserDetail();
        return self::ListSSL($currentuser['username']);
    }
	
	static function getResult()
    {
		 if (self::$ok) {
            return ui_sysmessage::shout(ui_language::translate("You SSL has been made now wait in about 5 min."), "zannounceok");
        }
		if (self::$delok) {
            return ui_sysmessage::shout(ui_language::translate("The selectet Certificate has been deletet."), "zannounceerror");
        }
		if (self::$error) {
            return ui_sysmessage::shout(ui_language::translate("A certificate with that name already exists must be erased first."), "zannounceerror");
        }
		if (self::$empty) {
            return ui_sysmessage::shout(ui_language::translate("A field was empty not allowed"), "zannounceerror");
        }
		if (self::$keyadd) {
            return ui_sysmessage::shout(ui_language::translate("Certificate Signing Request is made and sent to the mail you have enter"), "zannounceok");
        }
		if (self::$download) {
            return ui_sysmessage::shout(ui_language::translate("Your certificate is ready to be downloadet."), "zannounceok");
        }
        return;
    }
	
	 /**
     * Webinterface sudo methods.
     */
	
}
?>