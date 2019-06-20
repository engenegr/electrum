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

import os
import asyncio
import logging
import codecs

from PyQt5.QtCore import QThread, pyqtSignal, QAbstractTableModel, QVariant
from PyQt5.QtWidgets import QPushButton, QVBoxLayout, QLineEdit, QGridLayout, QProgressBar, QTableView, QHeaderView, QApplication

from electrum.network import Network
from electrum.transaction import TxOutput
from electrum.plugin import BasePlugin, hook
from electrum.i18n import _

from electrum.gui.qt.util import WindowModalDialog, get_parent_main_window, EnterButton, Buttons, CloseButton, OkButton, read_QIcon, CancelButton
from electrum.gui.qt.main_window import StatusBarButton
from electrum.bitcoin import is_address, TYPE_SCRIPT, TYPE_ADDRESS, dust_threshold
from functools import partial

from .omni import OmniCoreRPC

from PyQt5.QtCore import Qt, QModelIndex
from PyQt5.QtWidgets import QLabel, QMenu

#errors
from electrum.util import NotEnoughFunds, NoDynamicFeeEstimates
from electrum.wallet import InternalAddressCorruption

#TODO: set up logger for plugin output

class Plugin(BasePlugin):

    def __init__(self, parent, config, name):
        super().__init__(parent, config, name)
        self.parent = parent
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

        self.prepared_tx = ''
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
        #TODO: limit types of wallets plugin can work with
        pass

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
    def create_status_bar(self, parent):
        self.status_button = StatusBarButton(read_QIcon("omnilogo.png"), _("Omni"), lambda: self.show_omni_wallet_status(parent))
        parent.addPermanentWidget(self.status_button)

    def show_omni_wallet_status(self, window):
        d = WindowModalDialog(window, _("Omni Wallet Status"))

        vbox = QVBoxLayout(d)

        addresses = self.wallet.get_addresses()

        self.table_view = QTableView()

        self.table_view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table_view.customContextMenuRequested.connect(partial(self.create_menu, window))
        table = AddressTableModel()
        self.table_view.setModel(table)

        self.table_view.setFixedWidth(500)
        header = self.table_view.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        vbox.addWidget(self.table_view)

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
        thread = OmniNodeRequestTread(addresses, self._node, self.wallet, self._cache, loop, table)
        thread.pbar_signal.connect(pb.setValue)
        thread.pbar_signal_str.connect(status_label.setText)
        if not thread.isRunning():
            thread.start()
        if d.exec_():
            return


    def validate_omni(self, txid):
        '''
        queries omni node to get external knowledge of the tx state in omni layer
        :param tx: original bitcoin transaction
        :return: status, if validated or not
        '''
        tx_info = self.wallet.get_tx_height(txid)
        if tx_info.height == 0:
            return None
        if self._node:
            response = self._node.make_async_call(method='omni_gettransaction', params=[txid])
            if response:
                if 'result' in response and 'valid' in response['result']:
                    temp = response['result']
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

    def create_menu(self, parent, position):
        items = self.table_view.selectionModel().selectedIndexes()
        selected = list(x for x in items if x.column() == 0)
        if not selected or len(selected) > 1:
            return
        addrs = [self.table_view.model().data(item) for item in selected]
        menu = QMenu(parent)
        idx = self.table_view.indexAt(position)
        col = idx.column()
        column_title = self.table_view.model().headers[col]
        menu.addAction(_("Copy {}").format(column_title), lambda: self.place_text_on_clipboard(copy_text))
        copy_text =  self.table_view.model().data(idx)
        asset_info = self.table_view.model().getRowAsDict(idx)
        coins = self.wallet.get_addr_utxo(addrs[0])
        if coins:
            menu.addAction(_("Spend from"), lambda: self.spend_coins(parent, addrs[0], asset_info['asset'], asset_info['balance'] ))

        menu.exec_(self.table_view.viewport().mapToGlobal(position))

    def place_text_on_clipboard(self, text):
        if is_address(text):
            try:
                self.wallet.check_address(text)
            except InternalAddressCorruption as e:
                self.parent.show_error(str(e))
                raise
        qApp = QApplication.instance()
        qApp.clipboard().setText(text)

    def spend_coins(self, parent, address, asset, balance):
        coins = self.wallet.get_addr_utxo(address)
        d = WindowModalDialog(parent, _("Send Omni to Address"))
        d.setMinimumSize(100, 200)

        vbox = QVBoxLayout(d)

        vbox.addWidget(QLabel(_('Asset {}'.format(asset))))
        grid = QGridLayout()
        vbox.addLayout(grid)

        grid.addWidget(QLabel(_('Recepient')), 0, 0)
        recepient_field = QLineEdit()
        recepient_field.setText("")
        grid.addWidget(recepient_field, 0, 1)

        grid.addWidget(QLabel(_('Amount')), 1, 0)
        amount_field = QLineEdit()
        amount_field.setText(str(balance))
        grid.addWidget(amount_field, 1, 1)

        grid.addWidget(QLabel(_('Send onchain (sats)')), 2, 0)
        sats_field = QLineEdit()
        sats_field.setFixedWidth(280)
        sats_field.setText(str(dust_threshold()))
        grid.addWidget(sats_field, 2, 1 )

        FEERATE = 2

        grid.addWidget(QLabel(_('Fee (sat/vbyte)')), 3, 0)
        fee_field = QLineEdit()
        fee_field.setText(str(FEERATE))
        grid.addWidget(fee_field, 3, 1 )

        CheckTxButton = QPushButton(_("Check"))

        def check_handler(coins):
            recepient = str(recepient_field.text())
            try:
                amount = int(float(amount_field.text())*100000000)
            except:
                main_window = get_parent_main_window(parent)
                main_window.show_error("Coins amount must be numeric!")
                return
            try:
                onchain = int(sats_field.text())
            except:
                main_window = get_parent_main_window(parent)
                main_window.show_error("Sats amount must be integer!")
                return
            values = [item['value'] for item in coins.values()]
            maximum = max(values)
            idx = values.index(maximum)
            key_max = list(coins.keys())[idx]
            if not is_address(recepient):
                main_window = get_parent_main_window(parent)
                main_window.show_error("Non-valid destination address!")
                return
            if maximum < onchain + 1000:
                main_window = get_parent_main_window(parent)
                main_window.show_error("Not enough sats to send Omni!")
                return
            else:
                #coins = { key_max: coins[key_max] }
                asset_str = "%0.12x" % asset
                amount_str = "%0.16x" % amount
                opreturn_str = "OP_RETURN {}{}{}{}, 0 \n {}, {:d}".format('6f6d6e69', '0000', asset_str, amount_str, recepient, onchain )
                main_window = get_parent_main_window(parent)
                main_window.show_warning(opreturn_str)
                return

        CheckTxButton.clicked.connect(partial(check_handler, coins))

        ContinueButton = OkButton(d, label="Continue")
        def continue_handler():
            recepient = str(recepient_field.text())
            amount = int(float(amount_field.text()) * 100000000)
            onchain = int(sats_field.text())
            feerate = int(fee_field.text())
            opcode = '6a14'
            layer_hex = '6f6d6e69'
            amount_hex = '{0:0{1}X}'.format(amount,16)
            asset_hex = '{0:0{1}X}'.format(asset,12)
            omni_data = '{}{}{}{}{}'.format(opcode, layer_hex, "0000", asset_hex, amount_hex)
            #'6f6d6e69000000000000001f000000001dcd6500' # OP_RETURN  get_address_from_output_script(bfh(
            outputs = []
            outputs.append(TxOutput(TYPE_SCRIPT, omni_data, 0))
            outputs.append(TxOutput(TYPE_ADDRESS, recepient, onchain))
            network = Network.get_instance()
            fee_estimator = partial(network.config.estimate_fee_for_feerate, feerate*1000)
            coins = self.wallet.get_spendable_coins(domain=[address], config=network.config)
            coins.sort(key=lambda x: x['value'], reverse=False)
            spend_coin = None
            for c in coins:
                if c['value'] >= onchain + dust_threshold():
                    spend_coin = c
                    break
            try:
                btc_tx = self.wallet.make_unsigned_transaction([spend_coin], outputs, network.config,
                                                               fixed_fee=fee_estimator,
                                                               change_addr=address,
                                                               is_sweep=False)
                main_window = get_parent_main_window(parent)
                from electrum.gui.qt.transaction_dialog import show_transaction
                show_transaction(btc_tx, main_window, desc=None, prompt_if_unsaved=False)
                return
            except NotEnoughFunds as e:
                msg = "Not enough funds onchain. Send some bitcoins to {}".format(address)
            except NoDynamicFeeEstimates as e:
                msg = "Fee estimation error."
            except InternalAddressCorruption as e:
                msg = "Invalid address."
            except BaseException as e:
                msg = "Non-related to the wallet error {}".format(str(e))
            main_window = get_parent_main_window(parent)
            main_window.show_error(msg)
            return

        ContinueButton.clicked.connect(continue_handler)

        vbox.addStretch()
        vbox.addSpacing(13)
        vbox.addLayout(Buttons(CloseButton(d), CheckTxButton, ContinueButton))

        if not d.exec_():
            return


class OmniNodeRequestTread(QThread):
    pbar_signal = pyqtSignal(int)
    pbar_signal_str = pyqtSignal(str)
    def __init__(self, search_list, node, wallet, cache, loop, table):
        super(OmniNodeRequestTread, self).__init__()
        self.addresses = search_list
        self._node = node
        self._wallet = wallet
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
                        utxo_list = self._wallet.get_addr_utxo(a)
                        self._gui_obj.addAddress(Address(a, asset_balance['balance'], asset_balance['propertyid'], utxo_list))
            self.pbar_signal.emit(counter)
        self.pbar_signal_str.emit('completed')
        #measuring task time
        logging.debug("balances obtained. Task start {}, task end {}".format(time.time(), t))


class Address(object):
    """Name of the person along with his city"""
    def __init__(self, a, balance, asset, utxo_list):
        self.a = a
        self.balance = balance
        self.asset = asset
        self.utxo = str(len(utxo_list))

class AddressTableModel(QAbstractTableModel):

    def __init__(self):
        super(AddressTableModel, self).__init__()
        self.headers = ['Address', 'Asset', 'Balance', 'UTXOs']
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
                return str(address.a)
            elif col == 1:
                return str(address.asset)
            elif col == 2:
                return str(address.balance)
            elif col == 3:
                return str(address.utxo)
            return str("")

    def getRowAsDict(self, index):
        address = self.addresses[index.row()]
        return {'asset': address.asset, 'balance': address.balance}

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return QVariant()
        if orientation == Qt.Horizontal:
            return QVariant(self.headers[section])
        return QVariant(int(section + 1))