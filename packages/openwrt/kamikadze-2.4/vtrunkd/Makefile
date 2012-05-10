#
# Copyright (C) 2011 Andrew Gryaznov <realgrandrew@gmail.com>
#
# This is free software, licensed under the GNU General Public License v3 or higher.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=vtrunkd
PKG_VERSION:=0.1b
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=@SF/vtrunkd
PKG_MD5SUM:=e7ecdd95beb39e792fb371efce259f4f

include $(INCLUDE_DIR)/package.mk

define Package/vtrunkd
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+kmod-tun +libpthread
  TITLE:=Virtual trunking (bonding) daemon
  URL:=http://mxmit.com/vtrunkd
  SUBMENU:=VPN
endef

define Package/vtrunkd/conffiles
/etc/vtrunkd.conf
endef

CONFIGURE_ARGS += \
	--enable-nosem \
	--disable-mark

# these are reserved for future use
CONFIGURE_VARS += \
	LIBS="$(TARGET_LDFLAGS)" \
	BLOWFISH_HDR_DIR="$(STAGING_DIR)/usr/include/openssl" \
	LZO_HDR_DIR="$(STAGING_DIR)/usr/include/lzo" \
	SSL_HDR_DIR="$(STAGING_DIR)/usr/include/openssl" \

define Build/Compile
	$(call Build/Compile/Default,vtrunkd)
endef

define Package/vtrunkd/install
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/vtrunkd.conf $(1)/etc/
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/vtrunkd $(1)/usr/sbin/
endef

$(eval $(call BuildPackage,vtrunkd))
