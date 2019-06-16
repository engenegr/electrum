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
import codecs
from xmlrpc.client import ServerProxy

from PyQt5.QtCore import QRegExp, QObject, QThread, pyqtSignal, QAbstractTableModel, QVariant
from PyQt5.QtGui import QRegExpValidator
from PyQt5.QtWidgets import QLabel, QPushButton, QVBoxLayout, QLineEdit, QGridLayout, QProgressBar, QTableView

from electrum import util, keystore, ecc, crypto
from electrum.network import Network
from electrum import transaction
from electrum.gui.qt.address_list import AddressList
from electrum.plugin import BasePlugin, hook
from electrum.i18n import _
from electrum.wallet import Multisig_Wallet
#from electrum.util import (ThreadJob, make_dir, log_exceptions,
#                  make_aiohttp_session, resource_path)

from electrum.gui.qt.transaction_dialog import show_transaction
from electrum.gui.qt.util import WaitingDialog, WindowModalDialog, get_parent_main_window, line_dialog, text_dialog, EnterButton, Buttons, CloseButton, OkButton, HelpLabel, read_QIcon, CancelButton
from electrum.gui.qt.main_window import StatusBarButton
from functools import partial

import sys
import os
from .omni import OmniCoreRPC


from PyQt5.QtCore import Qt, QPersistentModelIndex, QModelIndex
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QFont
from PyQt5.QtWidgets import QAbstractItemView, QComboBox, QLabel, QMenu

from enum import IntEnum

from electrum.gui.qt.util import MyTreeView, MONOSPACE_FONT, ColorScheme

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
        self._cache = {}

        if self.node_url and self.node_user and self.node_pass:
            self._node = OmniCoreRPC(url=self.node_url, username=self.node_user, password=self.node_pass)
        else:
            self._node = None

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
                    LAYER = ""
                    VERSION = OP_RETURN[12:16]
                    ASSET = 0
                    try:
                        LAYER = codecs.decode(OP_RETURN[4:12], 'hex').decode('utf-8')
                    except:
                        logging.debug('exception while converting OP_RETURN field to decimal {}'.format(OP_RETURN[28:44]))
                        LAYER = "none"
                    try:
                        AMT = int(OP_RETURN[28:44], 16)
                    except:
                        logging.debug('exception while converting OP_RETURN field to decimal {}'.format(OP_RETURN[28:44]))
                        AMT = 0
                    try:
                        ASSET = int(OP_RETURN[16:28], 16)
                    except:
                        logging.debug('exception while converting OP_RETURN field to decimal {}'.format(OP_RETURN[28:44]))
                        ASSET = 0
                    # Tether Omni Layer condition
                    if LAYER == 'omni' and ASSET == 32:
                        logging.debug("found OMNI encoded OP_RETURN transcation {} amt {} USD".format(tx.txid(), AMT / 100000000))
        if AMT != -1:
            return {'layer': LAYER, 'asset': ASSET, 'value': AMT / 100000000 }
        else:
            return {}

    @hook
    def load_wallet(self, wallet, window):
        self.wallet = wallet
        #if self._cache.keys() != self.wallet.get_addresses() and False:
        #    self.update_omni_cache()
    '''
    def update_omni_cache(self):
        for a in self.wallet.get_addresses():
            if self._node:
                self._cache[a] = []
                response = self._node.make_async_call(method='omni_getallbalancesforaddress', params=[a])
                if response and 'result' in response:
                    for asset_balance in response['result']:
                        self._cache[a].append(dict(asset_balance))
                        logging.debug('{} asset {} balance cached'.format(a, asset_balance['propertyid'] ))
    '''
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

    @hook
    def create_send_tab(self, d):
        msg = _('Recipient of the funds.') + '\n\n'\
              + _('You may enter a Bitcoin address, a label from your list of contacts (a list of completions will be proposed), or an alias (email-like address that forwards to a Bitcoin address)')
        payto_label = HelpLabel(_('Pay to omni'), msg)
        d.addWidget(payto_label, 1, 0)
        pass

    @hook
    def create_status_bar(self, parent):
        self.status_button = StatusBarButton(read_QIcon("omnilogo.png"), _("Omni"), lambda: self.show_omni_wallet_status(parent))
        parent.addPermanentWidget(self.status_button)

    def show_omni_wallet_status(self, window):
        d = WindowModalDialog(window, _("Omni Wallet Status"))
        vbox = QVBoxLayout(d)

        addresses = self.wallet.get_addresses()

        view = QTableView()
        table = AddressTableModel()
        view.setModel(table)
        vbox.addWidget(view)

        pb = QProgressBar()
        pb.setMaximum(len(addresses))
        pb.setMinimum(0)
        vbox.addWidget(pb)

        grid = QGridLayout()
        grid.addWidget(QLabel(_("Status")), 1, 0)
        status_label = QLabel(_("starting..."))
        status_label.setFixedWidth(280)
        grid.addWidget(status_label, 1, 1)

        vbox.addLayout(grid)
        vbox.addLayout(Buttons(CancelButton(d), OkButton(d)))

        loop = asyncio.get_event_loop()
        thread = OmniNodeRequestTread(addresses, self._node, self._cache, loop, table)
        thread.pbar_signal.connect(pb.setValue)
        thread.pbar_signal_str.connect(status_label.setText)
        if not thread.isRunning():
            thread.start()
        if d.exec_():
            print("Exec!")


    def validate_omni(self, txid):
        '''
        queries omni node to get external knowledge of the tx state in omni layer
        :param tx: original bitcoin transaction
        :return: status, if validated or not
        '''
        if self._node:
            result = self._node.make_async_call(method='omni_gettransaction', params=[txid])
            if 'result' in result and 'valid' in result['result']:
                temp = result['result']
                return {'valid': temp['valid'],
                        'sendingaddress': temp['sendingaddress'],
                        'referenceaddress': temp['referenceaddress']}
        return None


    def view_omni_tx_dialog(self, parent, tx):
        info = self.get_omni_info(tx)
        if set(['layer', 'asset', 'value']) <= set(info.keys()):
            valid_dict = self.validate_omni(tx.txid())
            sender = None
            receiver = None
            verified = False
            if valid_dict:
                receiver = valid_dict['referenceaddress']
                sender = valid_dict['sendingaddress']
                verified = bool(valid_dict['valid'])
            asset_str = str(info['asset'])
            if info['asset'] == 31:
                asset_str = "USDT"
            amount_str = str("{:.8f}".format(info['value']))
            parent.show_message(''.join(["<b>",_("Layer"), ": </b>", _(info['layer']), "<br/>",
                                         "<b>", _("Asset"), ": </b> ", _(asset_str), "<br/>",
                                         "<b>", _("Amount"), ": </b> ", _(amount_str), "<br/>",
                                         "<b>", _("Verified"), ": </b>", _(str(verified)), "<br/>",
                                         "<b>", _("Sender"), ": </b>", _(str(sender)), "<br/>",
                                         "<b>", _("Recepient"), ": </b>", _(str(receiver)), "<br/>"
                                         ]),
                                rich_text=True)
        else:
            parent.show_message(''.join(["<b>",_("No omni info"),"</b>"]), rich_text=True)

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
            if self._node:
                status = self._node.check()
            else:
                self._node = OmniCoreRPC(url=self.node_url, username=self.node_user, password=self.node_pass)
                status = self._node.check()
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
            if self.wallet:
                self.wallet.syncronize()
                self.wallet.config.save_last_wallet()
            status = self._node.reset(url=self.node_url, username=self.node_user, password=self.node_pass)

        SaveButton.clicked.connect(save_handler)

        vbox.addStretch()
        vbox.addSpacing(13)
        vbox.addLayout(Buttons(CloseButton(d), CheckNodeButton, SaveButton))

        if not d.exec_():
            return

class OmniNodeRequestTread(QThread):
    pbar_signal = pyqtSignal(int)
    pbar_signal_str = pyqtSignal(str)
    def __init__(self, search_list, node, cache, loop, table):
        super(OmniNodeRequestTread, self).__init__()
        self.addresses = search_list
        self._node = node
        self._cache = cache
        self._loop = loop
        self._gui_obj = table

    def run(self):
        import time
        #for time measurement
        t = time.time()
        counter = 0
        for a in self.addresses:
            if self._node:
                self._cache[a] = []
                self.pbar_signal_str.emit(a)
                counter += 1
                response = self._node.make_async_call(method='omni_getallbalancesforaddress', params=[a], loop = self._loop)
                if response and 'result' in response:
                    for asset_balance in response['result']:
                        self._cache[a].append(dict(asset_balance))
                        logging.debug('{} asset {} balance cached'.format(a, asset_balance['propertyid']))
                        self._gui_obj.addAddress(Address(a, asset_balance['balance'], asset_balance['propertyid']))
            self.pbar_signal.emit(counter)
        self.pbar_signal_str.emit('completed')
        #measuring task time
        logging.debug("balances obtained. Task start {}, task end {}".format(time.time(), t))


class Address(object):
    """Name of the person along with his city"""
    def __init__(self, a, balance, asset):
        self.a = a
        self.balance = balance
        self.asset = asset

class AddressTableModel(QAbstractTableModel):

    def __init__(self):
        super(AddressTableModel, self).__init__()
        self.headers = ['Address', 'Asset', 'Balance']
        self.addresses = []

    def rowCount(self, index=QModelIndex()):
        return len(self.addresses)

    def addAddress(self, address):
        self.beginResetModel()
        self.addresses.append(address)
        self.endResetModel()

    def columnCount(self, index=QModelIndex()):
        return len(self.headers)

    def data(self, index, role=Qt.DisplayRole):
        col = index.column()
        address = self.addresses[index.row()]
        if role == Qt.DisplayRole:
            if col == 0:
                return QVariant(address.a)
            elif col == 1:
                return QVariant(address.asset)
            elif col == 2:
                return QVariant(address.balance)
            return QVariant()

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return QVariant()

        if orientation == Qt.Horizontal:
            return QVariant(self.headers[section])
        return QVariant(int(section + 1))





''' 
class UpdateCheckThread(QThread, PrintError):
    checked = pyqtSignal(object)
    failed = pyqtSignal()

    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window

    async def get_update_info(self):
        async with make_aiohttp_session(proxy=self.main_window.network.proxy) as session:
            async with session.get(UpdateCheck.url) as result:
                signed_version_dict = await result.json(content_type=None)
                # example signed_version_dict:
                # {
                #     "version": "3.9.9",
                #     "signatures": {
                #         "1Lqm1HphuhxKZQEawzPse8gJtgjm9kUKT4": "IA+2QG3xPRn4HAIFdpu9eeaCYC7S5wS/sDxn54LJx6BdUTBpse3ibtfq8C43M7M1VfpGkD5tsdwl5C6IfpZD/gQ="
                #     }
                # }
                version_num = signed_version_dict['version']
                sigs = signed_version_dict['signatures']
                for address, sig in sigs.items():
                    if address not in UpdateCheck.VERSION_ANNOUNCEMENT_SIGNING_KEYS:
                        continue
                    sig = base64.b64decode(sig)
                    msg = version_num.encode('utf-8')
                    if ecc.verify_message_with_address(address=address, sig65=sig, message=msg,
                                                       net=constants.BitcoinMainnet):
                        self.print_error(f"valid sig for version announcement '{version_num}' from address '{address}'")
                        break
                else:
                    raise Exception('no valid signature for version announcement')
                return StrictVersion(version_num.strip())
    
    def run(self):
        network = self.main_window.network
        if not network:
            self.failed.emit()
            return
        try:
            update_info = asyncio.run_coroutine_threadsafe(self.get_update_info(), network.asyncio_loop).result()
        except Exception as e:
            #self.print_error(traceback.format_exc())
            self.print_error(f"got exception: '{repr(e)}'")
            self.failed.emit()
        else:
            self.checked.emit(update_info)
'''