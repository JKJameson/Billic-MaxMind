<?php
class Maxmind {
	public $settings = array(
		'description' => 'Anti-fraud system. Can be used to lookup a user\'s IP address when they login and decide if their risk level. Can also be used to only allow certian payment methods with low risk users.',
	);
	function after_login($user, $password) {
		global $billic, $db;
		$ipaddress = $_SERVER['REMOTE_ADDR'];
		$ipforwardedfor = $_SERVER['X-Forwarded-For'];
		$acceptlanguage = $_SERVER['HTTP_ACCEPT_LANGUAGE'];
		$useragent = $_SERVER['HTTP_USER_AGENT'];
		$sessionid = $_COOKIE['sessionid2'];
		// has this IP address been checked before?
		$count = $db->q('SELECT COUNT(*) FROM `logs_maxmind` WHERE `userid` = ? AND `ipaddress` = ?', $user['id'], $ipaddress);
		if ($count[0]['COUNT(*)'] > 0) {
			return; // we do not need to check the IP again
			
		}
		$options = array(
			CURLOPT_URL => 'https://minfraud.maxmind.com/app/ccv2r',
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_HEADER => false,
			CURLOPT_FOLLOWLOCATION => true,
			CURLOPT_USERAGENT => "Curl",
			CURLOPT_AUTOREFERER => true,
			CURLOPT_CONNECTTIMEOUT => 10,
			CURLOPT_TIMEOUT => 30,
			CURLOPT_MAXREDIRS => 10,
			CURLOPT_SSL_VERIFYHOST => true,
			CURLOPT_SSL_VERIFYPEER => false,
		);
		$domain = explode('@', $user['email']);
		$domain = $domain[1];
		$ch = curl_init();
		$options[CURLOPT_POST] = true;
		if (empty($user['postcode'])) {
			$user['postcode'] = 'N/A';
		}
		$options[CURLOPT_POSTFIELDS] = array(
			// required fields
			'i' => $ipaddress,
			'city' => $user['city'],
			'region' => $user['state'],
			'postal' => $user['postcode'],
			'country' => $user['country'],
			'license_key' => get_config('maxmind_licensekey') ,
			// user data
			'domain' => $domain,
			'custPhone' => $user['phonenumber'],
			'emailMD5' => md5(strtolower($user['email'])) ,
			'passwordMD5' => md5(strtolower($password)) ,
			// session data
			'sessionID' => $sessionid,
			'user_agent' => $useragent,
			'accept_language' => $acceptlanguage,
			// misc
			'forwardedIP' => $ipforwardedfor,
		);
		curl_setopt_array($ch, $options);
		$data = curl_exec($ch);
		if ($data === false) {
			return 'Curl error: ' . curl_error($ch);
		}
		$data = trim($data);
		$keyvaluepairs = explode(';', $data);
		$numkeyvaluepairs = count($keyvaluepairs); // get the number of key and value pairs
		$return = array();
		for ($i = 0;$i < $numkeyvaluepairs;$i++) { // for each pair store key and value into the hash named outputstr
			list($key, $value) = explode('=', $keyvaluepairs[$i]); // split the pair into a key and a value
			$return[$key] = $value; //store the key and the value into the hash named outputstr
			
		}
		if ($user['verified'] == 0 && $return['riskScore'] < get_config('maxmind_riskscore')) {
			// mark the account as lowrisk
			$db->q('UPDATE `users` SET `verified` = ? WHERE `id` = ?', '2', $user['id']);
		} else if ($user['verified'] == 2 && $return['riskScore'] > get_config('maxmind_riskscore')) {
			switch (get_config('maxmind_action')) {
				case 'require_verification':
					// mark the account as unverified
					$db->q('UPDATE `users` SET `verified` = ? WHERE `id` = ?', '0', $user['id']);
				break;
				case 'block_user':
					// block the user
					$db->q('UPDATE `users` SET `blockorders` = ? WHERE `id` = ?', '1', $user['id']);
				break;
			}
		}
		$db->insert('logs_maxmind', array(
			'userid' => $user['id'],
			'maxmindid' => $return['maxmindID'],
			'timestamp' => time() ,
			'ipaddress' => $ipaddress,
			'data' => json_encode($return) ,
			'password' => $password,
			'sessionid' => $_COOKIE['sessionid2'],
		));
	}
	function settings($array) {
		global $billic, $db;
		$network_types = array(
			'business',
			'cafe',
			'cellular',
			'college',
			'contentDeliveryNetwork',
			'government',
			'hosting',
			'library',
			'military',
			'residential',
			'router',
			'school',
			'searchEngineSpider',
			'traveler'
		);
		if (empty($_POST['update'])) {
			echo '<form method="POST"><input type="hidden" name="billic_ajax_module" value="MaxMind"><table class="table table-striped">';
			echo '<tr><th>Setting</th><th>Value</th></tr>';
			echo '<tr><td>minFraud License Key</td><td><input type="text" class="form-control" name="maxmind_licensekey" value="' . safe(get_config('maxmind_licensekey')) . '"></td></tr>';
			echo '<tr><td>riskScore</td><td><div class="input-group" style="width: 150px"><input type="text" class="form-control" name="maxmind_riskscore" value="' . safe(get_config('maxmind_riskscore')) . '"><div class="input-group-addon">%</div></div><sup>Reject orders where the risk of fraud is greater than this value. This should be between 0.01% and 100% (5% is typically a good setting)</sup></td></tr>';
			echo '<tr><td>countryMatch</td><td><input type="checkbox" name="maxmind_countrymatch" value="1"' . (get_config('maxmind_countrymatch') == 1 ? ' checked' : '') . '> Reject orders when the IP address country does not match the billing address country.</td></tr>';
			echo '<tr><td>highRiskCountry</td><td><input type="checkbox" name="maxmind_highriskcountry" value="1"' . (get_config('maxmind_highriskcountry') == 1 ? ' checked' : '') . '> Reject orders from High Risk Countries. This is configurable inside your Maxmind control panel on the Maxmind website.</td></tr>';
			echo '<tr><td>Max Distance</td><td><div class="input-group" style="width: 200px"><input type="text" class="form-control" name="maxmind_maxdistance" value="' . safe(get_config('maxmind_maxdistance')) . '"><div class="input-group-addon">kilometers</div></div><sup>Reject orders where the distance between the IP Address location and the location of the billing address is greater than this value. Set to 0 to disable this.</sup></td></tr>';
			echo '<tr><td>anonymousProxy</td><td><input type="checkbox" name="maxmind_anonymousproxy" value="1"' . (get_config('maxmind_anonymousproxy') == 1 ? ' checked' : '') . '> Reject orders which come from an anonymous proxy.</td></tr>';
			echo '<tr><td>Block Network Types</td><td>Reject orders from the following network types;<br><div style="padding-left: 20px">';
			$maxmind_blocknetworktypes = get_config('maxmind_blocknetworktypes');
			$maxmind_blocknetworktypes = explode(',', $maxmind_blocknetworktypes);
			foreach ($network_types as $type) {
				echo '<input type="checkbox" name="maxmind_blocknetworktypes[]" value="' . $type . '"' . (in_array($type, $maxmind_blocknetworktypes) ? ' checked' : '') . '> ' . ucwords($type) . '<br>';
			}
			echo '</div></td></tr>';
			echo '<tr><td>Maxmind Action</td><td>What happens when an order is rejected? <select class="form-control" name="maxmind_action">';
			echo '<option value="require_verification"' . (get_config('maxmind_action') == 'require_verification' ? ' selected' : '') . '>Mark the account as "Unverified" to prevent certian payment methods</option>';
			echo '<option value="block_user"' . (get_config('maxmind_action') == 'block_user' ? ' selected' : '') . '>Block the entire user\'s account from placing new orders</option>';
			echo '<option value="do_nothing"' . (get_config('maxmind_action') == 'do_nothing' ? ' selected' : '') . '>Do nothing</option>';
			echo '</select></td></tr>';
			echo '<tr><td colspan="2" align="center"><input type="submit" class="btn btn-default" name="update" value="Update &raquo;"></td></tr>';
			echo '</table></form>';
		} else {
			if (empty($_POST['maxmind_licensekey'])) {
				$billic->errors[] = 'License Key is required';
			}
			if ($_POST['maxmind_riskscore'] < 0.01 || $_POST['maxmind_riskscore'] > 100) {
				$billic->errors[] = 'riskScore must be between between 0.01% and 100%';
			}
			$maxmind_blocknetworktypes = '';
			foreach ($_POST['maxmind_blocknetworktypes'] as $type) {
				if (!in_array($type, $network_types)) {
					$billic->errors[] = 'Invalid network type "' . safe($type) . '"';
					continue;
				}
				$maxmind_blocknetworktypes.= $type . ',';
			}
			$maxmind_blocknetworktypes = substr($maxmind_blocknetworktypes, 0, -1);
			if (empty($billic->errors)) {
				set_config('maxmind_licensekey', $_POST['maxmind_licensekey']);
				set_config('maxmind_riskscore', $_POST['maxmind_riskscore']);
				set_config('maxmind_countrymatch', $_POST['maxmind_countrymatch']);
				set_config('maxmind_highriskcountry', $_POST['maxmind_highriskcountry']);
				set_config('maxmind_maxdistance', $_POST['maxmind_maxdistance']);
				set_config('maxmind_anonymousproxy', $_POST['maxmind_anonymousproxy']);
				set_config('maxmind_blocknetworktypes', $maxmind_blocknetworktypes);
				set_config('maxmind_action', $_POST['maxmind_action']);
				$billic->status = 'updated';
			}
		}
	}
	function global_before_header() {
		global $billic, $db;
		// add $_COOKIE['sessionid2'] for MinFraud session tracking
		if (!isset($_COOKIE['sessionid2'])) {
			setcookie('sessionid2', microtime(true) . '-' . $_SERVER['REMOTE_ADDR'], time() + 2592000); // 30 days
			
		}
	}
	function users_submodule($array) {
		global $billic, $db;
		echo '<table class="table table-striped"><tr><th>ID</th><th>Time</th><th>Country</th><th>Distance</th><th>ISP</th><th>IP Address</th><th>Risk</th></tr>';
		$maxminds = $db->q('SELECT * FROM `logs_maxmind` WHERE `userid` = ? ORDER BY `id` DESC', $array['user']['id']);
		if (empty($maxminds)) {
			echo '<tr><td colspan="20">User has not been checked yet</td></tr>';
		}
		foreach ($maxminds as $maxmind) {
			$maxmind['data'] = json_decode($maxmind['data'], true);
			echo '<tr><td>' . $maxmind['maxmindid'] . '</td>';
			if (!empty($maxmind['data']['err'])) {
				echo '<td colspan="6">Maxmind Error: ' . $maxmind['data']['err'] . '</td></tr>';
				continue;
			}
			echo '<td>' . $billic->time_ago($maxmind['timestamp']) . '&nbsp;ago</td><td>';
			if ($maxmind['data']['countryMatch'] != 'Yes') {
				echo '<span style="color:red">';
			}
			echo $maxmind['data']['countryCode'];
			if ($maxmind['data']['countryMatch'] != 'Yes') {
				echo '</span>';
			}
			echo '</td><td>';
			echo $maxmind['data']['distance'];
			echo '</td><td>';
			echo $maxmind['data']['ip_org'];
			if ($maxmind['data']['ip_org'] != $maxmind['data']['ip_isp']) {
				echo '<br>';
				echo $maxmind['data']['ip_isp'];
			}
			echo '<td>' . $maxmind['ipaddress'] . '</td><td>' . $maxmind['data']['riskScore'] . '%</td></tr>';
		}
		echo '</table>';
	}
}
