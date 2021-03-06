<?php

/**
 * Implements provider availability, holdings.
 */
function openruth_availability_holdings($provider_ids) {
  $res = openruth_client_invoke('get_holdings', $provider_ids);
  if (is_string($res->holding)) {
    watchdog('openruth', '@method error: “@message”', array('@method' => 'get_holdings', '@message' => $res->holding), WATCHDOG_ERROR);
    return array();
  }
  return _openruth_get_holdings($res);
}

/**
 * Implements provider availability issues.
 */
function openruth_availability_issues($provider_ids) {
  return openruth_availability_holdings($provider_ids);
}

/**
 * Implements provider availability_availability.
 */
function openruth_availability_availability($provider_ids) {
  $availability = array();
  $holdings = openruth_client_invoke('get_holdings', $provider_ids);

  foreach ($holdings->holding as $item) {
    $id = $item->itemId;
    $availability_text = NULL;

    // For service version 1.0.
    if (!empty($item->agencyHoldings->itemAvailability)) {
      $availability_text = $item->agencyHoldings->itemAvailability;
    }
    // For service version 1.1.
    if (!empty($item->holdingAgency[0]->agencyHoldings)) {
      $availability_text = $item->holdingAgency[0]->agencyHoldings
        ->itemAvailability;
    }

    $available = $availability_text ==
      'copies available for loan and reservation';
    $reservable = $available || $availability_text ==
      'no copies available, but item can be reserved';

    $availability[$id] = array(
      'local_id' => $id,
      'available' => $available,
      'reservable' => $reservable,
      'show_reservation_button' => $reservable,
    );
  }
  return $availability;
}

/**
 * @param $res; a json encoded response from openruth-client (get_holdings)
 * @return mixed; an array with holding-information OR an errorstring OR FALSE
 */
function _openruth_get_holdings($res) {
  if (isset($res->agencyError)) {
    return $res->agencyError;
  }
  elseif (isset($res->holding)) {
    return _openruth_set_holdings($res);
  }
  else {
    return FALSE;
  }
}

/**
 * @param $res; a json encoded response from openruth-client (get_holdings)
 * @return array; an array with holding-information
 */
function _openruth_set_holdings($res) {
  $holdings = array();
  foreach ($res->holding as $holding) {
    $h = _openruth_init_holding($holding);
    $itemHoldings = isset($holding->itemHoldings) ? $holding->itemHoldings : NULL;

    // For 1.1 version. Override the path.
    if (isset($holding->holdingAgency[0]->itemHoldings)) {
      $itemHoldings = $holding->holdingAgency[0]->itemHoldings;
    }

    if (isset($itemHoldings)) {
      foreach ($itemHoldings as $itemHolding) {
        // remember to count ordersCount
        $h['reserved_count'] += $itemHolding->ordersCount;
        _openruth_set_locations($h, $itemHolding);
        _openruth_set_periodicals($h, $itemHolding);
      }
    }
    if ($h['is_periodical']) {
      $h['holdings'] = _openruth_periodicals_unique_holdings($h['holdings']);
    }
    _openruth_set_table_html($h);
    $holdings[$holding->itemId] = $h;
  }
  return $holdings;
}

/**
 * @param $holding; json encoded holdingpart from openruth-client (get_holdings)
 * @return array; initialized holding array set with default values
 */
function _openruth_init_holding($holding) {
  $holdings = isset($holding->agencyHoldings) ? $holding->agencyHoldings : NULL;

  // For 1.1 version. Override the path.
  if (isset($holding->holdingAgency[0]->agencyHoldings)) {
    $holdings = $holding->holdingAgency[0]->agencyHoldings;
  }

  if (isset($holdings)) {
    $available = $holdings->itemAvailability == 'copies available for loan and reservation';
    $reservable = $available || $holdings->itemAvailability == 'no copies available, but item can be reserved';
  }
  else {
    $available = FALSE;
    $reservable = FALSE;
  }
  $holding = array(
    'local_id' => $holding->itemId,
    'available' => $available,
    'reservable' => $reservable,
    'show_reservation_button' => $reservable,
    'holdings' => array(),
    'holdings_available' => array(),
    'reserved_count' => isset($holding->ordersCount) ? (int) $holding->ordersCount : 0,
    'total_count' => 0,
    'reservable_count' => 0,
    'issues' => array(),
    'is_periodical' => FALSE,
  );

  // check if number of copies available (copiesAvailableCount) is > 0; if not set available to false
  if ($holding['available'] && ($available < 1)) {
    $holding['available'] = FALSE;
  }

  return $holding;
}

/**
 * make a html-table
 * @params $h; holding information for a given material
 * @return; a html table
 */
function _openruth_set_table_html(&$h) {
  // set a classname for styling the table
  $variables['attributes'] = array(
    'class' => array(
      drupal_html_class('availability_holdings_table'),
    ),
  );
  // set table header
  $variables['header'] = array(
    'placement' => t('Placement'),
    'copies' => t('Copies'),
    'home' => t('At home'),
  );
  // set table rows
  $variables['rows'] = _openruth_set_rows($h);
  // theme the table
  // @TODO; move this to ding_availability ??
  $html = theme('table', $variables);

  $h['html'] = $html;
}

/**
 * set table rows for given holdings
 * @param $h; holding information for a given material
 * @return array; an array for rendering
 */
function _openruth_set_rows($h) {
  $rows = array();
  if (isset($h['holdings'])) {
    foreach ($h['holdings'] as $key => $data) {
      $row = array();
      $row['placement'] = $data['placement'];
      $row['copies'] = $data['copiesCount'];
      $row['home'] = $data['copiesAvailableCount'];
      $rows[] = $row;
    }
    // Add row (totals).
    $row = array();
    $row['data']['Library'] = t('Total');
    $row['data']['Copies'] = $h['total_count'];
    $row['data']['Home'] = $h['reservable_count'];
    $row['class'] = array(drupal_html_class('availability_holdings_last_row'));
    $rows[] = $row;

    // Add last row (reservations).
    $row = array();
    $row['data']['Library'] = t('Reservations');
    $row['data']['Copies'] = array('data' => $h['reserved_count'], 'colspan' => 2);
    $rows[] = $row;
  }


  return $rows;
}

/**
 * special method for periodicals. iterate holdings and make a unique entry for each branch
 * @param; $holdings; array of holdings for a periodical
 * @return; array; with unique holdings for each branch
 */
function _openruth_periodicals_unique_holdings($holdings) {
  $uh = array();
  foreach ($holdings as $holding) {
    $key = $holding['agencyBranchCode'];
    // first iteration or new branchcode
    if (empty($uh) || !isset($uh[$key])) {
      $uh[$key] = $holding;
      continue;
    }
    // same branch; increase copiesCount and copiesAvailableCount
    $uh[$key]['copiesCount'] += $holding['copiesCount'];
    $uh[$key]['copiesAvailableCount'] += isset($holding['copiesAvailableCount']) ? $holding['copiesAvailableCount'] : 0;
  }
  return $uh;
}

/**
 *
 */
function _openruth_set_periodicals(&$h, $itemHolding) {
  if (isset($itemHolding->itemSerialPartId) || isset($itemHolding->itemSerialPartVolume) || isset($itemHolding->itemSerialPartIssue)) {
    $issue = array(
      'local_id' => $itemHolding->itemSerialPartId,
      'orders_count' => $itemHolding->ordersCount,
      'provider' => 'openruth',
    );

    $item_loc = isset($itemHolding->itemLocation) ? $itemHolding->itemLocation : $itemHolding->itemComingLocation;

    foreach ($item_loc as $location) {
      $loc = array();
      if (isset($location->agencyBranchId->agencyBranchName)) {
        $loc[] = $location->agencyBranchId->agencyBranchName;
      }

      if (isset($location->agencyCollectionId->agencyCollectionName)) {
        $loc[] = $location->agencyCollectionId->agencyCollectionName;
      }

      if (isset($location->agencyPlacementId->agencyPlacementName)) {
        $loc[] = $location->agencyPlacementId->agencyPlacementName;
      }

      $issue['placement'][] = array(
        'location' => implode(' > ', $loc),
        'available_count' => isset($location->copiesAvailableCount) ? $location->copiesAvailableCount : 0,
        'total_count' => $location->copiesCount,
        'reservable' => $location->orderAllowed,
      );
    }

    $h['issues'][$itemHolding->itemSerialPartVolume][$itemHolding->itemSerialPartIssue] = $issue;
    // set flag for periodical
    $h['is_periodical'] = TRUE;
  }
}

function _openruth_set_locations(&$h, $itemHolding) {
  $holding_reservable = FALSE;
  $fields = array('itemLocation', 'itemComingLocation');

  foreach ($fields as $field) {
    if (isset($itemHolding->{$field})) {
      foreach ($itemHolding->{$field} as $itemLocation) {
        $data = array();

        $location_available = 0;

        if ($itemLocation->orderAllowed) {
          $holding_reservable = TRUE;
        }
        //$total += $itemLocation->copiesCount;
        $h['total_count'] += $itemLocation->copiesCount;

        $data['copiesCount'] = $itemLocation->copiesCount;

        if (isset($itemLocation->copiesAvailableCount)) {
          //$available += $itemLocation->copiesAvailableCount;
          $h['reservable_count'] += $itemLocation->copiesAvailableCount;
          // pjo;
          $location_available += $itemLocation->copiesAvailableCount;

          $data['copiesAvailableCount'] = $itemLocation->copiesAvailableCount;

        }
        $parts = array();
        if (isset($itemLocation->agencyBranchId->agencyBranchName)) {
          $parts[] = $itemLocation->agencyBranchId->agencyBranchName;

          $data['agencyBranchName'] = $itemLocation->agencyBranchId->agencyBranchName;
          $data['agencyBranchCode'] = $itemLocation->agencyBranchId->agencyBranchCode;

        }

        if (isset($itemLocation->agencyDepartmentId->agencyDepartmentName)) {
          $parts[] = $itemLocation->agencyDepartmentId->agencyDepartmentName;

          $data['agencyDepartmentName'] = $itemLocation->agencyDepartmentId->agencyDepartmentName;
        }
        if (isset($itemLocation->agencyCollectionId->agencyCollectionName)) {
          $parts[] = $itemLocation->agencyCollectionId->agencyCollectionName;

          $data['agencyCollectionName'] = $itemLocation->agencyCollectionId->agencyCollectionName;
        }
        if (isset($itemLocation->agencyPlacementId->agencyPlacementName)) {
          $parts[] = $itemLocation->agencyPlacementId->agencyPlacementName;

          $data['agencyPlacementName'] = $itemLocation->agencyPlacementId->agencyPlacementName;
        }
        if ($parts) {
          $data['placement'] = join(' → ', $parts);
          $h['holdings'][] = $data;
        }
        if ($parts && ($location_available > 0)) {
          $h['holdings_available'][] = join(' → ', $parts);
        }
      }
    }
  }
}
