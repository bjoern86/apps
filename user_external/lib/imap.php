<?php
/**
 * Copyright (c) 2012 Robin Appelman <icewind@owncloud.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

/**
 * User authentication against an IMAP mail server
 *
 * @category Apps
 * @package  UserExternal
 * @author   Robin Appelman <icewind@owncloud.com>
 * @license  http://www.gnu.org/licenses/agpl AGPL
 * @link     http://github.com/owncloud/apps
 */
class OC_User_IMAP extends \OCA\user_external\Base {
	private $mailbox;
	private $domain;

	/**
	 * Create new IMAP authentication provider
	 *
	 * @param string $mailbox PHP imap_open mailbox definition, e.g.
	 *                        {127.0.0.1:143/imap/readonly}
	 * @param string $domain  If provided, loging will be restricted to this domain
	 */
	public function __construct($mailbox, $domain = '') {
		parent::__construct($mailbox);
		$this->mailbox=$mailbox;
		$this->domain=$domain;
	}

	/**
	 * Check if the password is correct without logging in the user
	 *
	 * @param string $uid      The username
	 * @param string $password The password
	 *
	 * @return true/false
	 */
	public function checkPassword($uid, $password) {
		if (!function_exists('imap_open')) {
			OCP\Util::writeLog('user_external', 'ERROR: PHP imap extension is not installed', OCP\Util::ERROR);
			return false;
		}

		// Check if we only want logins from given domains
 		if($this->domain != '') {	
			$domains = explode(',', $this->domain);
			// only one domain allowed
			if(count($domains) == 1) {
				$pieces = explode('@', $uid);
				if(count($pieces) == 1) {
					$username = $uid . "@" . $this->domain;
				}elseif((count($pieces) == 2) and ($pieces[1] == $this->domain)) {
					$username = $uid;
					$uid = $pieces[0]; // strip the domain part from UID if only one domain allowed
				}else{
					return false; // domain within uid not the allowed domain
				}
			}
			// more than one domain allowed
			elseif(count($domains) > 1) {
				$domains = array_filter(array_map('trim', $domains));
				$pieces = explode('@', $uid);
				if (in_array($pieces[1], $domains)) {
					$username = $uid;
				}
				else {
					return false; // domain within uid not in array of allowed domains
				}
			}
 		}else{	// no domain given at all, all domains allowed
 			$username = $uid;
 		}
 
 		$mbox = @imap_open($this->mailbox, $username, $password, OP_HALFOPEN, 1);
		imap_errors();
		imap_alerts();
		if($mbox !== FALSE) {
			imap_close($mbox);
			$uid = mb_strtolower($uid);
			$this->storeUser($uid);
			return $uid;
		}else{
			return false;
		}
	}
}
