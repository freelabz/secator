WP_CLI=wp-cli --allow-root

install: configure

configure:
	sleep 15
	@echo "⚙️ Configuring Wordpress database..."
	@rm -f wp-config.php
	$(WP_CLI) core config \
		--dbhost=${WORDPRESS_DB_HOST} \
		--dbname=${WORDPRESS_DB_NAME} \
		--dbuser=${WORDPRESS_DB_USER} \
		--dbpass=${WORDPRESS_DB_PASSWORD} \
		--path=${WORDPRESS_INSTALL_PATH} \
		--locale=${WORDPRESS_LOCALE} \
		--skip-check

	@echo "⚙️Configuring Wordpress parameters..."
	$(WP_CLI) core install \
		--url=${WORDPRESS_WEBSITE_URL_WITHOUT_HTTP} \
		--title="$(WORDPRESS_WEBSITE_TITLE)" \
		--admin_user=${WORDPRESS_ADMIN_USER} \
		--admin_password=${WORDPRESS_ADMIN_PASSWORD} \
		--admin_email=${WORDPRESS_ADMIN_EMAIL}

	$(WP_CLI) option update siteurl "${WORDPRESS_WEBSITE_URL}"
	$(WP_CLI) rewrite structure $(WORDPRESS_WEBSITE_POST_URL_STRUCTURE)