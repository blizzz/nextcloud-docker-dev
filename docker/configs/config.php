<?php $CONFIG=[
	'debug' => true,
	'apps_paths' => 
	array (
		0 => 
		array (
			'path' => '/var/www/html/apps',
			'url' => '/apps',
			'writable' => false,
		),
		1 => 
		array (
			'path' => '/var/www/html/apps-extra',
			'url' => '/apps-extra',
			'writable' => false,
		),
		2 => 
		array (
			'path' => '/var/www/html/apps-writable',
			'url' => '/apps-writable',
			'writable' => true,
		),
	),
	'trusted_domains' => [
		0 => 'localhost',
		1 => 'local.dev.bitgrid.net',
		2 => 'nextcloud.local.dev.bitgrid.net'
	],

	'overwrite.cli.url' => 'https://nextcloud.local.dev.bitgrid.net/'

	// config for mailhog
	'mail_from_address' => 'admin',
	'mail_smtpmode' => 'smtp',
	'mail_sendmailmode' => 'smtp',
	'mail_domain' => 'localhost',
	'mail_smtphost' => 'mail',
	'mail_smtpport' => '1025',

	//PLACEHOLDER
];