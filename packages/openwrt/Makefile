#
# Copyright (C) 2011 Andrew Gryaznov <realgrandrew@gmail.com>
#
# This is free software, licensed under the GNU General Public License v3 or higher.
# See /LICENSE for more information.
#
# share source in vtrunkd folder
#

include $(TOPDIR)/rules.mk

PKG_NAME:=vtrunkd
PKG_VERSION:=0.1b
PKG_RELEASE:=1

#PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
#PKG_SOURCE_URL:=@SF/vtrunkd
#PKG_MD5SUM:=793975b5dbc5525c702dad796ba4a47f

include $(INCLUDE_DIR)/package.mk

define Package/vtrunkd
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+kmod-tun +libpthread +flex +bison +librt
  TITLE:=Virtual trunking (bonding) daemon
  URL:=http://mxmit.com/vtrunkd
  SUBMENU:=VPN
endef

define Package/vtrunkd/conffiles
/etc/vtrunkd.conf
endef

CONFIGURE_ARGS += \
	--prefix= \
	--enable-json \
	--disable-o3 \
	--enable-client-only
#	--enable-low-mem

# these are reserved for future use
CONFIGURE_VARS += \
	LIBS="$(TARGET_LDFLAGS)" \
	BLOWFISH_HDR_DIR="$(STAGING_DIR)/usr/include/openssl" \
	LZO_HDR_DIR="$(STAGING_DIR)/usr/include/lzo" \
	SSL_HDR_DIR="$(STAGING_DIR)/usr/include/openssl" \
	CXX="mipsel-openwrt-linux-uclibc-g++"

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./vtrunkd-src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(call Build/Compile/Default,vtrunkd)
	$(CP) $(PKG_BUILD_DIR)/vtrunkd $(PKG_BUILD_DIR)/../../../
endef

define Package/vtrunkd/install
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/vtrunkd.conf $(1)/etc/
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/vtrunkd $(1)/usr/sbin/
#	$(CP) $(PKG_BUILD_DIR)/vtrunkd $(PKG_BUILD_DIR)/../../../
endef

$(eval $(call BuildPackage,vtrunkd))
