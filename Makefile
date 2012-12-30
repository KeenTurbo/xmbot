include $(TOPDIR)/rules.mk

PKG_NAME:=xmbot
PKG_RELEASE:=0.1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)
PKG_CONFIG_DEPENDS := \
	CONFIG_PACKAGE_xmbot

include $(INCLUDE_DIR)/package.mk

define Package/xmbot/default
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=XMPP
  TITLE:=xmbot - XMPP bot for openwrt
  DEPENDS:=+libiksemel
  MAINTAINER:=wgjtyu <wgjtyu@gmail.com>
endef

define Package/xmbot
  $(Package/xmbot/default)
  MENU:=1
endef

define Package/xmbot/description
 xmbot is a xmpp bot for openwrt
endef

TARGET_CFLAGS += $(TLS_CFLAGS)
TARGET_LDFLAGS += -Wl,-rpath-link=$(STAGING_DIR)/usr/lib

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/xmbot/conffiles
/etc/xmbotrc
endef

define Package/xmbot/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/xmbot.init $(1)/etc/init.d/xmbot
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/xmbotrc $(1)/etc/xmbotrc
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/xmbot $(1)/usr/sbin/xmbot
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/control_wireless.sh $(1)/usr/sbin/control_wireless.sh
endef

$(eval $(call BuildPackage,xmbot))
