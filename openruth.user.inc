<?php

/**
 * Implements provider user, authenticate.
 */
function openruth_user_authenticate($name, $pass) {
  $return = array(
    'success' => FALSE,
  );
  $res = openruth_client_invoke('user_check', $name, $pass);

  if (is_string($res)) {
    watchdog('openruth', 'Error in user_check: @error', array('@error' => $res), WATCHDOG_ERROR);
    throw new DingProviderAuthException($res);
  }
  elseif (!$res || !$res->userFound || !$res->userPinCodeOk) {
    // No reply or not found.
    throw new DingProviderAuthException('User not found or incorrect password.');
  }
  elseif ($res->userBlocked) {
    throw new DingProviderUserException('User is blocked');
  }

  $return['creds'] = array(
    'name' => $name,
    'pass' => $pass,
  );

  $userStatus = _openruth_user_status($return['creds'], TRUE);

  if (is_string($userStatus)) {
    throw new DingProviderAuthException('Could not fetch user data. Temporary service issue.');
  }
  elseif (is_object($userStatus) && isset($userStatus->userInfo)) {
    $userInfo = $userStatus->userInfo;

    $display_name = NULL;
    if (!empty($userInfo->userFirstName)) {
      $display_name = $userInfo->userFirstName;
    }
    if (!empty($userInfo->userLastName)) {
      $display_name = ' ' . $userInfo->userLastName;
    }
    $display_name = trim($display_name);

    // @todo Need a default value if both first and last name are empty.
    // if (empty($display_name)) {
    //   $display_name = t('User');
    // }

    $return['user'] = array(
      'data' => array(
        'display_name' => $display_name,
      ),
    );
    $return['private']['userinfo'] = $userInfo;

    if (isset($userInfo->userEmail)) {
      $return['user']['mail'] = $userInfo->userEmail;
    }

    $return['success'] = TRUE;
  }

  return $return;
}

/**
 *
 */
function openruth_user_profile_init($profile, $auth_res) {
  openruth_profile_update($profile, $auth_res['private']['userinfo']);
  // Don't save to Openruth in presave hook.
  $profile->openruth_init = TRUE;
  $profile->save();
  unset($profile->openruth_init);
}

/**
 * Update user account.
 */
function openruth_user_account_update($account, $changes) {
  $result = array();
  $creds = ding_user_get_creds($account);
  $res = openruth_client_invoke('update_userinfo', $creds['name'], $creds['pass'], $changes);
  if ($res !== TRUE) {
    // Call failed, throw exception.
    if (is_string($res)) {
      $exception_message = t('Update userinfo failed, message: @message', array('@message' => $res));
    }
    else {
      $exception_message = t('Update userinfo failed.');
    }
    throw new Exception($exception_message);
  }


  if (isset($changes['pass'])) {
    // Set new password.
    $creds['pass'] = $changes['pass'];
    // Update creds.
    $result['creds'] = $creds;

    // Update user status cache.
    _openruth_user_status($creds, TRUE);
  }
  return $result;
}


/**
 * Clear user cache.
 */
function openruth_user_clear_cache($account) {
  $creds = ding_user_get_creds($account);
  // Update user status cache.
  _openruth_user_status($creds, TRUE);
}
