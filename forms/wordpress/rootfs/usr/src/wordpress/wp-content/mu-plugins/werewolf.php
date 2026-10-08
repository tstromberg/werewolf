<?php
/**
 * Plugin Name: werewolf
 * Description: What the wordpress form settles for every site on it: mail by SMTP submission to the relay the machine's settings name, and the defaults WordPress's code leaves to a plugin (docs/wordpress.md).
 * Author: werewolf
 */

defined( 'ABSPATH' ) || exit;

// --- mail --------------------------------------------------------------------
// By SMTP submission (tcp/587, STARTTLS) to the relay the settings name,
// with the password the config brought. Without a relay, mail is off and
// says so on the console, rather than tried through a sendmail that is not
// there.
add_filter(
	'pre_wp_mail',
	function ( $null, $atts ) {
		if ( ! empty( $GLOBALS['werewolf_site']['smtp'] ) ) {
			return $null;
		}
		$to = is_array( $atts['to'] ?? null ) ? implode( ', ', $atts['to'] ) : (string) ( $atts['to'] ?? '' );
		error_log( 'wordpress: mail to ' . $to . ' not sent: no mail relay (the smtp setting)' );
		return false;
	},
	10,
	2
);
add_action(
	'phpmailer_init',
	function ( $phpmailer ) {
		$site = $GLOBALS['werewolf_site'];
		if ( empty( $site['smtp'] ) ) {
			return;
		}
		$colon = strrpos( $site['smtp'], ':' );
		$host  = trim( substr( $site['smtp'], 0, $colon ), '[]' );
		$port  = (int) substr( $site['smtp'], $colon + 1 );
		$phpmailer->isSMTP();
		$phpmailer->Host       = $host;
		$phpmailer->Port       = $port;
		$phpmailer->SMTPSecure = 587 === $port ? 'tls' : 'ssl';
		$phpmailer->SMTPAuth   = ! empty( $site['smtp-user'] );
		if ( $phpmailer->SMTPAuth ) {
			$phpmailer->Username = $site['smtp-user'];
			$phpmailer->Password = rtrim( (string) @file_get_contents( '/run/svc/php-fpm/smtp-password' ), "\r\n" );
		}
		if ( ! empty( $site['mail-from'] ) ) {
			$phpmailer->setFrom( $site['mail-from'], $site['title'] ?? 'WordPress', false );
		}
	}
);

// --- pingbacks ----------------------------------------------------------------
// XML-RPC stays, for the mobile apps and Jetpack; pingbacks, which make the
// site fetch URLs for strangers and amplify floods, do not.
add_filter(
	'xmlrpc_methods',
	function ( $methods ) {
		unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );
		return $methods;
	}
);
add_filter(
	'wp_headers',
	function ( $headers ) {
		unset( $headers['X-Pingback'] );
		return $headers;
	}
);
add_filter( 'pings_open', '__return_false' );
add_filter( 'pre_option_default_ping_status', fn() => 'closed' );
add_filter( 'pre_option_default_pingback_flag', fn() => 0 );

// --- who the users are --------------------------------------------------------
// Login names are listed over REST only to those logged in, and ?author=N
// does not redirect to a name.
add_filter(
	'rest_endpoints',
	function ( $endpoints ) {
		if ( is_user_logged_in() ) {
			return $endpoints;
		}
		foreach ( array_keys( $endpoints ) as $route ) {
			if ( str_starts_with( $route, '/wp/v2/users' ) ) {
				unset( $endpoints[ $route ] );
			}
		}
		return $endpoints;
	}
);
add_action(
	'parse_request',
	function ( $wp ) {
		if ( ! is_admin() && ! is_user_logged_in() && isset( $_GET['author'] ) ) {
			status_header( 404 );
			nocache_headers();
			exit;
		}
	}
);
add_filter( 'oembed_response_data', fn( $data ) => array_diff_key( $data, array_flip( array( 'author_name', 'author_url' ) ) ) );

// --- the console --------------------------------------------------------------
// Security events, one line each, through php-fpm's log to the console.
add_action( 'wp_login', fn( $login, $user ) => error_log( sprintf( 'wordpress: login %s (user %d) from %s', $login, $user->ID, $_SERVER['REMOTE_ADDR'] ?? '?' ) ), 10, 2 );
add_action( 'wp_login_failed', fn( $login ) => error_log( sprintf( 'wordpress: login failed for %s from %s', $login, $_SERVER['REMOTE_ADDR'] ?? '?' ) ) );
add_action( 'application_password_failed_authentication', fn() => error_log( sprintf( 'wordpress: application password refused from %s', $_SERVER['REMOTE_ADDR'] ?? '?' ) ) );
add_action( 'set_user_role', fn( $user_id, $role ) => error_log( sprintf( 'wordpress: user %d is now %s', $user_id, $role ) ), 10, 2 );
add_action( 'after_password_reset', fn( $user ) => error_log( sprintf( 'wordpress: password reset for user %d', $user->ID ) ) );
