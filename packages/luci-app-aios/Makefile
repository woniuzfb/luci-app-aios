include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-aios
PKG_VERSION:=3.0.0
PKG_RELEASE:=1

PKG_LICENSE:=MIT
PKG_MAINTAINER:=luci-app-aios contributors
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
	SECTION:=luci
	CATEGORY:=LuCI
	SUBMENU:=3. Applications
	TITLE:=LuCI Support for Xray & V2Ray (AIOS)
	DEPENDS:=+luci-base +rpcd +uci +ca-bundle \
		+PACKAGE_AIOS_INCLUDE_FW4:firewall4 \
		+PACKAGE_AIOS_INCLUDE_FW4:kmod-nft-tproxy \
		+PACKAGE_AIOS_INCLUDE_FW3:iptables \
		+PACKAGE_AIOS_INCLUDE_FW3:iptables-mod-tproxy \
		+PACKAGE_AIOS_INCLUDE_FW3:ipset \
		+PACKAGE_AIOS_INCLUDE_XRAY:aios-xray \
		+PACKAGE_AIOS_INCLUDE_V2RAY:aios-v2ray \
		+PACKAGE_AIOS_INCLUDE_GEODATA:aios-geodata
	PKGARCH:=all
endef

define Package/$(PKG_NAME)/description
	Unified LuCI application and standalone Vite+Vue3 web console for both Xray-core and V2Ray (v2fly), supporting firewall4 (nftables) and legacy firewall3 (iptables/ipset).
endef

define Package/$(PKG_NAME)/config
menu "luci-app-aios Configuration"
	depends on PACKAGE_$(PKG_NAME)

config PACKAGE_AIOS_INCLUDE_FW4
	bool "Depend on firewall4 + kmod-nft-tproxy (OpenWrt 22.03+)"
	default n

config PACKAGE_AIOS_INCLUDE_FW3
	bool "Depend on iptables + ipset + iptables-mod-tproxy (OpenWrt 19.07/21.02)"
	default n

config PACKAGE_AIOS_INCLUDE_XRAY
	bool "Depend on aios-xray (from openwrt-aios)"
	default n

config PACKAGE_AIOS_INCLUDE_V2RAY
	bool "Depend on aios-v2ray (from openwrt-aios)"
	default n

config PACKAGE_AIOS_INCLUDE_GEODATA
	bool "Depend on aios-geodata (from openwrt-aios)"
	default n

endmenu
endef

define Build/Compile
endef

define Package/$(PKG_NAME)/conffiles
/etc/config/aios
/etc/aios/
endef

define Package/$(PKG_NAME)/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	mkdir -p /var/etc/aios
	if [ -f /etc/uci-defaults/90-luci-aios ]; then
		( . /etc/uci-defaults/90-luci-aios ) && rm -f /etc/uci-defaults/90-luci-aios
	fi
	rm -rf /tmp/luci-indexcache* /tmp/luci-modulecache/
	/etc/init.d/rpcd reload >/dev/null 2>&1 || true
fi
exit 0
endef

define Package/$(PKG_NAME)/postrm
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	rm -rf /tmp/luci-indexcache* /tmp/luci-modulecache/
fi
exit 0
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/etc/config $(1)/etc/init.d $(1)/etc/hotplug.d/iface $(1)/etc/uci-defaults $(1)/etc/aios/presets
	$(INSTALL_DATA) ./root/etc/config/aios $(1)/etc/config/aios
	$(INSTALL_BIN) ./root/etc/init.d/aios $(1)/etc/init.d/aios
	$(INSTALL_BIN) ./root/etc/hotplug.d/iface/90-aios-gateway $(1)/etc/hotplug.d/iface/90-aios-gateway
	$(INSTALL_BIN) ./root/etc/uci-defaults/90-luci-aios $(1)/etc/uci-defaults/90-luci-aios

	$(INSTALL_DIR) $(1)/usr/libexec/rpcd
	$(INSTALL_BIN) ./root/usr/libexec/rpcd/luci.aios $(1)/usr/libexec/rpcd/luci.aios

	$(INSTALL_DIR) $(1)/usr/share/luci/menu.d $(1)/usr/share/rpcd/acl.d $(1)/usr/share/nftables.d/ruleset-post
	$(INSTALL_DATA) ./root/usr/share/luci/menu.d/luci-app-aios.json $(1)/usr/share/luci/menu.d/luci-app-aios.json
	$(INSTALL_DATA) ./root/usr/share/rpcd/acl.d/luci-app-aios.json $(1)/usr/share/rpcd/acl.d/luci-app-aios.json
	$(INSTALL_DATA) ./root/usr/share/nftables.d/ruleset-post/90-aios.nft $(1)/usr/share/nftables.d/ruleset-post/90-aios.nft

	$(INSTALL_DIR) $(1)/usr/share/aios/common $(1)/usr/share/aios/adapter $(1)/usr/share/aios/firewall
	$(INSTALL_BIN) ./root/usr/share/aios/gen_config.uc $(1)/usr/share/aios/gen_config.uc
	$(INSTALL_DATA) ./root/usr/share/aios/dnsmasq.ut $(1)/usr/share/aios/dnsmasq.ut
	$(INSTALL_DATA) ./root/usr/share/aios/common/config.mjs $(1)/usr/share/aios/common/config.mjs
	$(INSTALL_DATA) ./root/usr/share/aios/common/capabilities.mjs $(1)/usr/share/aios/common/capabilities.mjs
	$(INSTALL_DATA) ./root/usr/share/aios/common/core_features.json $(1)/usr/share/aios/common/core_features.json
	$(INSTALL_DATA) ./root/usr/share/aios/common/features.mjs $(1)/usr/share/aios/common/features.mjs
	$(INSTALL_DATA) ./root/usr/share/aios/common/stream.mjs $(1)/usr/share/aios/common/stream.mjs
	$(INSTALL_DATA) ./root/usr/share/aios/adapter/xray.mjs $(1)/usr/share/aios/adapter/xray.mjs
	$(INSTALL_DATA) ./root/usr/share/aios/adapter/v2ray.mjs $(1)/usr/share/aios/adapter/v2ray.mjs
	$(INSTALL_DATA) ./root/usr/share/aios/adapter/v2ray_v5.mjs $(1)/usr/share/aios/adapter/v2ray_v5.mjs
	$(INSTALL_DATA) ./root/usr/share/aios/firewall/fw4_nft.ut $(1)/usr/share/aios/firewall/fw4_nft.ut
	$(INSTALL_BIN) ./root/usr/share/aios/firewall/fw3_ipt.sh $(1)/usr/share/aios/firewall/fw3_ipt.sh
	$(INSTALL_BIN) ./root/usr/share/aios/firewall/gateway.uc $(1)/usr/share/aios/firewall/gateway.uc
	$(INSTALL_BIN) ./root/usr/share/aios/core_manager.sh $(1)/usr/share/aios/core_manager.sh

	$(INSTALL_DIR) $(1)/www/luci-static/resources/view/aios
	$(INSTALL_DATA) ./root/www/luci-static/resources/view/aios/entry.js $(1)/www/luci-static/resources/view/aios/entry.js

	$(INSTALL_DIR) $(1)/www/aios
	$(CP) ./root/www/aios/* $(1)/www/aios/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
