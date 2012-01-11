<?php

function vulnscan_admin_settings($form, &$form_state) {
    /* Main settings */
    $form['vulnscan_skipfish_settings'] = array(
        '#type' => 'fieldset',
        '#title' => t('Skipfish Settings'),
        '#collapsible' => TRUE,
        '#collapsed' => FALSE,
    );

    $form['vulnscan_skipfish_settings']['skipfish_location'] = array(
        '#type' => 'textfield',
        '#title' => t('Skipfish Location'),
        '#default_value' => variable_get('vulnscan_skipfish_location', '/usr/local/bin/skipfish'),
        '#size' => 30,
    );

    /* Server settings */
    $form['vulnscan_server_settings'] = array(
        '#type' => 'fieldset',
        '#title' => 'Available Servers',
        '#collapsible' => TRUE,
        '#collapsed' => FALSE,
    );

    $form['vulnscan_server_settings']['servers'] = array(
        '#type' => 'select',
        '#title' => t('Existing Servers'),
        '#options' => array('None' => t('None')),
    );

    $form['submit'] = array(
        '#type' => 'submit',
        '#value' => t('Save Settings'),
    );

    return $form;
}

function vulnscan_admin_settings_submit($form, &$form_state) {
    variable_set('vulnscan_skipfish_location', $form_state['values']['skipfish_location']);
}
