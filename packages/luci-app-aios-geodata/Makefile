include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-aios-geodata
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
	TITLE:=GeoData browser & asset integration for luci-app-aios
	DEPENDS:=+luci-app-aios
	PKGARCH:=all
endef

define Package/$(PKG_NAME)/description
	Optional GeoIP/GeoSite menu integration and asset helpers for luci-app-aios.
endef

define Build/Compile
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/share/luci/menu.d $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) ./root/usr/share/luci/menu.d/luci-app-aios-geodata.json $(1)/usr/share/luci/menu.d/luci-app-aios-geodata.json
	$(INSTALL_DATA) ./root/usr/share/rpcd/acl.d/luci-app-aios-geodata.json $(1)/usr/share/rpcd/acl.d/luci-app-aios-geodata.json
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
