#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2014 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import asyncio
import aiohttp
import logging
import concurrent
from xmlrpc.client import ServerProxy

from PyQt5.QtCore import QRegExp, QObject, pyqtSignal
from PyQt5.QtGui import QRegExpValidator
from PyQt5.QtWidgets import QLabel, QPushButton, QVBoxLayout, QLineEdit, QGridLayout

from electrum import util, keystore, ecc, crypto
from electrum.network import Network
from electrum import transaction
from electrum.plugin import BasePlugin, hook
from electrum.i18n import _
from electrum.wallet import Multisig_Wallet
#from electrum.util import (ThreadJob, make_dir, log_exceptions,
#                  make_aiohttp_session, resource_path)

from electrum.gui.qt.transaction_dialog import show_transaction
from electrum.gui.qt.util import WaitingDialog, WindowModalDialog, get_parent_main_window, line_dialog, text_dialog, EnterButton, Buttons, CloseButton, OkButton
from functools import partial

import sys
import os
from .omni import OmniCoreRPC

#TODO: set up logger for plugin output


class Plugin(BasePlugin):

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.omni_assets_codes = []

        self.base_dir = os.path.join(config.electrum_path(), 'omniviewer')

        if self.config.get('omni_node') is None:
            self.config.set_key('omni_node', 'https://127.0.0.1:18332/')
        if self.config.get('omni_user') is None:
            self.config.set_key('omni_user', 'user')
        if self.config.get('omni_pass') is None:
            self.config.set_key('omni_pass', 'none')

        self.node_url = self.config.get('omni_node')
        self.node_user = self.config.get('omni_user')
        self.node_pass = self.config.get('omni_pass')

        if self.node_url and self.node_user and self.node_pass:
            self.node = OmniCoreRPC(url=self.node_url, username=self.node_user, password=self.node_pass)
        else:
            self.node = None

    def requires_settings(self):
        return True

    def settings_widget(self, window):
        return EnterButton(_('Node setup'), partial(self.node_settings_dialog, window))

    def password_dialog(self, msg=None, parent=None):
        from electrum.gui.qt.password_dialog import PasswordDialog
        parent = parent or self
        d = PasswordDialog(parent, msg)
        return d.run()

    @hook
    def init_qt(self, gui):
        for window in gui.windows:
            self.on_new_window(window)

    @hook
    def on_new_window(self, window):
        self.update(window)

    @hook
    def on_close_window(self, window):
        self.update(window)

    def is_available(self):
        return True

    def update(self, window):
        pass
        #wallet = window.wallet
        #TODO: limit types of wallets plugin can work with
        #if type(wallet) != Multisig_Wallet:
        #    return

    def get_omni_info(self, tx):
        AMT = -1
        for out in tx.outputs():
            if out.type == 2:
                OP_RETURN = str(out.address)
                if len(OP_RETURN) == 44:
                    LAYER = OP_RETURN[0:12]
                    VERSION = OP_RETURN[12:16]
                    ASSET = OP_RETURN[16:28]
                    try:
                        AMT = int(OP_RETURN[28:44], 16)
                    except:
                        logging.debug('exception while converting OP_RETURN field to decimal {}'.format(OP_RETURN[28:44]))
                        AMT = 0
                    # Tether Omni Layer condition
                    if LAYER == '6a146f6d6e69' and ASSET == '00000000001f':
                        logging.debug("found OMNI encoded OP_RETURN transcation {} amt {} USD".format(tx.txid(), AMT / 100000000))
        if AMT != -1:
            return [AMT / 100000000, "USDT"]
        else:
            return []


    @hook
    def transaction_dialog(self, d):
        if self.get_omni_info(d.tx) != []:
            d.omni_view_button = b = QPushButton(_("View Omni"))
            b.clicked.connect(lambda: self.view_omni_tx_dialog(d, d.tx))
            d.buttons.insert(0, b)
        self.transaction_dialog_update(d)

    @hook
    def transaction_dialog_update(self, d):
        #TODO: omni tx validation
        if d.tx.is_complete() and self.get_omni_info(d.tx) != []:
            d.omni_view_button.show()
        elif self.get_omni_info(d.tx) != []:
            d.omni_view_button.hide()
        return

    def validate_omni(self, tx):
        '''
        queries omni node to get external knowledge of the tx state in omni layer
        :param tx: original bitcoin transaction
        :return: status, if validated or not
        '''
        pass

    def view_omni_tx_dialog(self, parent, tx):
        info = self.get_omni_info(tx)
        parent.show_message(''.join(["<b>",_("Verified"), ": </b>", _(str(False)), "<br/>",
                                     "<b>", _("Amount"), ": </b> ", _(str(info[0])), "<br/>",
                                     "<b>", _("Asset"), ": </b> ", _(str(info[1]))
                                     ]),
                            rich_text=True)

        """
        d = WindowModalDialog(self, "Omni Transaction Dialog")
        d.setMinimumWidth(500)
        d.setMinimumHeight(210)
        d.setMaximumHeight(450)
        d.setContentsMargins(11, 11, 1, 1)
        self.c_dialog = d

        vbox = QVBoxLayout()
        vbox.addWidget(QLabel(_("Transaction ID:")))
        window.exec_layout(vbox, next_enabled=False, raise_on_cancel=False)
        return bool(d.exec_())
        """

    '''
    def cosigner_can_sign(self, tx, cosigner_xpub):
        from electrum.keystore import is_xpubkey, parse_xpubkey
        xpub_set = set([])
        for txin in tx.inputs():
            for x_pubkey in txin['x_pubkeys']:
                if is_xpubkey(x_pubkey):
                    xpub, s = parse_xpubkey(x_pubkey)
                    xpub_set.add(xpub)
        return cosigner_xpub in xpub_set
    
    def do_send(self, tx):
        def on_success(result):
            window.show_message(_("Your transaction was sent to the cosigning pool.") + '\n' +
                                _("Open your cosigner wallet to retrieve it."))
        def on_failure(exc_info):
            e = exc_info[1]
            try: self.logger.error("on_failure", exc_info=exc_info)
            except OSError: pass
            window.show_error(_("Failed to send transaction to cosigning pool") + ':\n' + str(e))

        for window, xpub, K, _hash in self.cosigner_list:
            if not self.cosigner_can_sign(tx, xpub):
                continue
            # construct message
            raw_tx_bytes = bfh(str(tx))
            public_key = ecc.ECPubkey(K)
            message = public_key.encrypt_message(raw_tx_bytes).decode('ascii')
            # send message
            task = lambda: server.put(_hash, message)
            msg = _('Sending transaction to cosigning pool...')
            WaitingDialog(window, msg, task, on_success, on_failure)
        '''
    def node_settings_dialog(self, window):

        d = WindowModalDialog(window, _("Omni Plugin - Trusted Node Settings"))
        d.setMinimumSize(100, 200)

        vbox = QVBoxLayout(d)
        vbox.addWidget(QLabel(''.join(["<br/>", _("Select trusted Omnicore node (or any other node with similar RPC)"),"<br/>",
                                       _("the plugin will acquire transcaction status in Omni Layer"), "<br/>","<br/>",
                                    ])))

        self.node_url = self.config.get('omni_node')
        self.node_user = self.config.get('omni_user')
        self.node_pass = self.config.get('omni_pass')

        vbox.addWidget(QLabel(_('Node settings:')))
        grid = QGridLayout()
        vbox.addLayout(grid)

        grid.addWidget(QLabel(_('Url')), 0, 0)
        url_field = QLineEdit()
        url_field.setText(str(self.node_url))
        grid.addWidget(url_field, 0, 1)

        grid.addWidget(QLabel(_('User')), 1, 0)
        user_field = QLineEdit()
        user_field.setText(str(self.node_user))
        grid.addWidget(user_field, 1, 1)

        grid.addWidget(QLabel(_('Password')), 2, 0)
        pass_field = QLineEdit()
        #pass_field.setValidator(QRegExpValidator(QRegExp('[1-9]+'), None))
        pass_field.setEchoMode(QLineEdit.Password)
        pass_field.setText(str(self.node_pass))
        grid.addWidget(pass_field, 2, 1)

        CheckNodeButton = QPushButton(_("Check"))
        def check_handler():
            status = {}
            if self.node:
                status = self.node.check()
            else:
                self.node = OmniCoreRPC(url=self.node_url, username=self.node_user, password=self.node_pass)
                status = self.node.check()
            if 'error' not in status:
                d.show_message("Node is ok!")
            elif 'error' in status:
                d.show_error(''.join(
                    ["<b>", _("Plugin can't connect"), ": </b>", _(status['error']),
                     "<br/>"]),
                    rich_text=True)
            else:
                d.show_error("Unknown error!")
        CheckNodeButton.clicked.connect(check_handler)

        SaveButton = OkButton(d, label="Save\Quit")
        def save_handler():
            self.node_url = str(url_field.text())
            self.config.set_key('omni_node', self.node_url)
            self.node_user = str(user_field.text())
            self.config.set_key('omni_user', self.node_user)
            self.node_pass = str(pass_field.text())
            self.config.set_key('omni_pass', self.node_pass)
            status = self.node.reset(url=self.node_url, username=self.node_user, password=self.node_pass)

        SaveButton.clicked.connect(save_handler)

        vbox.addStretch()
        vbox.addSpacing(13)
        vbox.addLayout(Buttons(CloseButton(d), CheckNodeButton, SaveButton))

        if not d.exec_():
            return