<?php
require_once('helpers.inc');

function vulnscan_scan_form($form, &$form_state) {
    global $user;
    $groups = user_scannable_groups($user);
    $servers = array();
    $sites = get_all_sites_assoc();

    foreach ($groups as $group)
        foreach (get_all_servers_in_server_group_assoc($group) as $key => $value)
            $servers[$key] = $value;

    if (count($groups) == 0) {
        $form['vulnscan_nogroups'] = array(
            '#type' => 'markup',
            '#prefix' => '<div>',
            '#markup' => t('No scannable groups'),
            '#suffix' => '</div>',
        );

        return $form;
    }

    $form['vulnscan_scan_server_groups'] = array(
        '#type' => 'fieldset',
        '#title' => t('Scan Server Groups'),
    );

    $form['vulnscan_scan_server_groups']['groups'] = array(
        '#type' => 'select',
        '#multiple' => TRUE,
        '#options' => $groups,
    );

    $form['vulnscan_scan_servers'] = array(
        '#type' => 'fieldset',
        '#title' => t('Scan Individual Servers'),
    );

    $form['vulnscan_scan_servers']['servers'] = array(
        '#type' => 'select',
        '#multiple' => TRUE,
        '#options' => $servers,
    );

    $form['vulnscan_scan_host'] = array(
        '#type' => 'select',
        '#title' => t('Site to Scan'),
        '#options' => $sites,
    );

    $form['submit'] = array(
        '#type' => 'submit',
        '#value' => 'Run Scan',
    );

    return $form;
}

function vulnscan_scan_form_submit($form, &$form_state) {
    global $user;
    $site = $form_state['values']['vulnscan_scan_host'];

    if (isset($form_state['values']['groups'])) {
        foreach (array_filter($form_state['values']['groups']) as $group) {
            if (user_can_scan_group($user, $group) == false) {
                drupal_set_message(t('Invalid group: @group', array('@group' => $group)), 'error');
                continue;
            }

            if (run_scan_on_server_group($site, $group) == false)
                return;
        }
    }

    if (isset($form_state['values']['servers'])) {
        foreach (array_filter($form_state['values']['servers']) as $server) {
            if (user_can_scan_server($user, $server) == false) {
                drupal_set_message(t('Invalid server: @server', array('@server' => $server)), 'error');
                continue;
            }

            run_scan_on_server($site, $server);
        }
    }
}
