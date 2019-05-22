# -*- mode: python3 -*-
import os
import sys
import threading
import traceback

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

from electroncash import Wallet, WalletStorage
from electroncash.util import UserCancelled, InvalidPassword
from electroncash.base_wizard import BaseWizard
from electroncash.i18n import _

from .seed_dialog import SeedLayout, KeysLayout
from .network_dialog import NetworkChoiceLayout
from .util import *
from .password_dialog import PasswordLayout, PW_NEW
from .bip38_importer import Bip38Importer


class GoBack(Exception):
    pass

MSG_GENERATING_WAIT = _("Electron Cash is generating your addresses, please wait...")
MSG_ENTER_ANYTHING = _("Please enter a seed phrase, a master key, a list of "
                       "Bitcoin addresses, or a list of private keys")
MSG_ENTER_SEED_OR_MPK = _("Please enter a seed phrase or a master key (xpub or xprv):")
MSG_COSIGNER = _("Please enter the master public key of cosigner #{}:")
MSG_ENTER_PASSWORD = _("Choose a password to encrypt your wallet keys.") + '\n'\
                     + _("Leave this field empty if you want to disable encryption.")
MSG_RESTORE_PASSPHRASE = \
    _("Please enter your seed derivation passphrase. "
      "Note: this is NOT your encryption password. "
      "Leave this field empty if you did not use one or are unsure.")


class CosignWidget(QWidget):
    size = 120

    def __init__(self, m, n):
        QWidget.__init__(self)
        self.R = QRect(0, 0, self.size, self.size)
        self.setGeometry(self.R)
        self.setMinimumHeight(self.size)
        self.setMaximumHeight(self.size)
        self.m = m
        self.n = n

    def set_n(self, n):
        self.n = n
        self.update()

    def set_m(self, m):
        self.m = m
        self.update()

    def paintEvent(self, event):
        bgcolor = self.palette().color(QPalette.Background)
        pen = QPen(bgcolor, 7, Qt.SolidLine)
        qp = QPainter()
        qp.begin(self)
        qp.setPen(pen)
        qp.setRenderHint(QPainter.Antialiasing)
        qp.setBrush(Qt.gray)
        for i in range(self.n):
            alpha = int(16* 360 * i/self.n)
            alpha2 = int(16* 360 * 1/self.n)
            qp.setBrush(Qt.green if i<self.m else Qt.gray)
            qp.drawPie(self.R, alpha, alpha2)
        qp.end()



def wizard_dialog(func):
    def func_wrapper(*args, **kwargs):
        run_next = kwargs['run_next']
        wizard = args[0]
        wizard.back_button.setText(_('Back') if wizard.can_go_back() else _('Cancel'))
        try:
            out = func(*args, **kwargs)
        except GoBack:
            wizard.go_back() if wizard.can_go_back() else wizard.close()
            return
        except UserCancelled:
            return
        #if out is None:
        #    out = ()
        if type(out) is not tuple:
            out = (out,)
        run_next(*out)
    return func_wrapper



# WindowModalDialog must come first as it overrides show_error
class InstallWizard(QDialog, MessageBoxMixin, BaseWizard):

    accept_signal = pyqtSignal()
    synchronized_signal = pyqtSignal(str)

    def __init__(self, config, app, plugins, storage):
        BaseWizard.__init__(self, config, storage)
        QDialog.__init__(self, None)
        self.setWindowTitle('Electron Cash  -  ' + _('Install Wizard'))
        self.app = app
        self.config = config
        # Set for base base class
        self.plugins = plugins
        self.language_for_seed = config.get('language')
        self.setMinimumSize(600, 400)
        self.accept_signal.connect(self.accept)
        self.title = QLabel()
        self.main_widget = QWidget()
        self.back_button = QPushButton(_("Back"), self)
        self.back_button.setText(_('Back') if self.can_go_back() else _('Cancel'))
        self.next_button = QPushButton(_("Next"), self)
        self.next_button.setDefault(True)
        self.logo = QLabel()
        self.please_wait = QLabel(_("Please wait..."))
        self.please_wait.setAlignment(Qt.AlignCenter)
        self.icon_filename = None
        self.loop = QEventLoop()
        self.rejected.connect(lambda: self.loop.exit(0))
        self.back_button.clicked.connect(lambda: self.loop.exit(1))
        self.next_button.clicked.connect(lambda: self.loop.exit(2))
        outer_vbox = QVBoxLayout(self)
        inner_vbox = QVBoxLayout()
        inner_vbox.addWidget(self.title)
        inner_vbox.addWidget(self.main_widget)
        inner_vbox.addStretch(1)
        inner_vbox.addWidget(self.please_wait)
        inner_vbox.addStretch(1)
        scroll_widget = QWidget()
        scroll_widget.setLayout(inner_vbox)
        scroll = QScrollArea()
        scroll.setWidget(scroll_widget)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setWidgetResizable(True)
        icon_vbox = QVBoxLayout()
        icon_vbox.addWidget(self.logo)
        icon_vbox.addStretch(1)
        hbox = QHBoxLayout()
        hbox.addLayout(icon_vbox)
        hbox.addSpacing(5)
        hbox.addWidget(scroll)
        hbox.setStretchFactor(scroll, 1)
        outer_vbox.addLayout(hbox)
        outer_vbox.addLayout(Buttons(self.back_button, self.next_button))
        self.set_icon(':icons/electron-cash.png')
        self.show()
        self.raise_()
        self.refresh_gui()  # Need for QT on MacOSX.  Lame.

    def run_and_get_wallet(self):

        vbox = QVBoxLayout()
        hbox = QHBoxLayout()
        hbox.addWidget(QLabel(_('Wallet') + ':'))
        self.name_e = QLineEdit()
        hbox.addWidget(self.name_e)
        button = QPushButton(_('Choose...'))
        hbox.addWidget(button)
        vbox.addLayout(hbox)

        self.msg_label = QLabel('')
        vbox.addWidget(self.msg_label)
        hbox2 = QHBoxLayout()
        self.pw_e = QLineEdit('', self)
        self.pw_e.setFixedWidth(150)
        self.pw_e.setEchoMode(2)
        self.pw_label = QLabel(_('Password') + ':')
        hbox2.addWidget(self.pw_label)
        hbox2.addWidget(self.pw_e)
        hbox2.addStretch()
        vbox.addLayout(hbox2)
        self.set_layout(vbox, title=_('Electron Cash wallet'))

        wallet_folder = os.path.dirname(self.storage.path)

        def on_choose():
            path, __ = QFileDialog.getOpenFileName(self, "Select your wallet file", wallet_folder)
            if path:
                self.name_e.setText(path)

        def on_filename(filename):
            path = os.path.join(wallet_folder, filename)
            try:
                self.storage = WalletStorage(path, manual_upgrades=True)
                self.next_button.setEnabled(True)
            except IOError:
                self.storage = None
                self.next_button.setEnabled(False)
            if self.storage:
                if not self.storage.file_exists():
                    msg =_("This file does not exist.") + '\n' \
                          + _("Press 'Next' to create this wallet, or choose another file.")
                    pw = False
                elif self.storage.file_exists() and self.storage.is_encrypted():
                    msg = _("This file is encrypted.") + '\n' + _('Enter your password or choose another file.')
                    pw = True
                else:
                    msg = _("Press 'Next' to open this wallet.")
                    pw = False
            else:
                msg = _('Cannot read file')
                pw = False
            self.msg_label.setText(msg)
            if pw:
                self.pw_label.show()
                self.pw_e.show()
                self.pw_e.setFocus()
            else:
                self.pw_label.hide()
                self.pw_e.hide()

        button.clicked.connect(on_choose)
        self.name_e.textChanged.connect(on_filename)
        n = os.path.basename(self.storage.path)
        self.name_e.setText(n)

        while True:
            password = None
            if self.storage.file_exists() and not self.storage.is_encrypted():
                break
            if self.loop.exec_() != 2:  # 2 = next
                return
            if not self.storage.file_exists():
                break
            if self.storage.file_exists() and self.storage.is_encrypted():
                password = self.pw_e.text()
                try:
                    self.storage.decrypt(password)
                    break
                except InvalidPassword as e:
                    QMessageBox.information(None, _('Error'), str(e))
                    continue
                except BaseException as e:
                    traceback.print_exc(file=sys.stdout)
                    QMessageBox.information(None, _('Error'), str(e))
                    return

        path = self.storage.path
        if self.storage.requires_split():
            self.hide()
            msg = _("The wallet '{}' contains multiple accounts, which are no longer supported since Electrum 2.7.\n\n"
                    "Do you want to split your wallet into multiple files?").format(path)
            if not self.question(msg):
                return
            file_list = '\n'.join(self.storage.split_accounts())
            msg = _('Your accounts have been moved to') + ':\n' + file_list + '\n\n'+ _('Do you want to delete the old file') + ':\n' + path
            if self.question(msg):
                os.remove(path)
                self.show_warning(_('The file was removed'))
            return

        if self.storage.requires_upgrade():
            self.hide()
            msg = _("The format of your wallet '%s' must be upgraded for Electron Cash. This change will not be backward compatible"%path)
            if not self.question(msg):
                return
            self.storage.upgrade()
            self.wallet = Wallet(self.storage)
            return self.wallet, password

        action = self.storage.get_action()
        if action and action != 'new':
            self.hide()
            msg = _("The file '{}' contains an incompletely created wallet.\n"
                    "Do you want to complete its creation now?").format(path)
            if not self.question(msg):
                if self.question(_("Do you want to delete '{}'?").format(path)):
                    os.remove(path)
                    self.show_warning(_('The file was removed'))
                return
            self.show()
        if action:
            # self.wallet is set in run
            self.run(action)
            return self.wallet, password

        self.wallet = Wallet(self.storage)
        return self.wallet, password



    def finished(self):
        """Called in hardware client wrapper, in order to close popups."""
        return

    def on_error(self, exc_info):
        if not isinstance(exc_info[1], UserCancelled):
            traceback.print_exception(*exc_info)
            self.show_error(str(exc_info[1]))

    def set_icon(self, filename):
        prior_filename, self.icon_filename = self.icon_filename, filename
        self.logo.setPixmap(QPixmap(filename).scaledToWidth(60))
        return prior_filename

    def set_layout(self, layout, title=None, next_enabled=True):
        self.title.setText("<b>%s</b>"%title if title else "")
        self.title.setVisible(bool(title))
        # Get rid of any prior layout by assigning it to a temporary widget
        prior_layout = self.main_widget.layout()
        if prior_layout:
            QWidget().setLayout(prior_layout)
        self.main_widget.setLayout(layout)
        self.back_button.setEnabled(True)
        self.next_button.setEnabled(next_enabled)
        if next_enabled:
            self.next_button.setFocus()
        self.main_widget.setVisible(True)
        self.please_wait.setVisible(False)

    def exec_layout(self, layout, title=None, raise_on_cancel=True,
                        next_enabled=True):
        self.set_layout(layout, title, next_enabled)
        result = self.loop.exec_()
        if not result and raise_on_cancel:
            raise UserCancelled
        if result == 1:
            raise GoBack
        self.title.setVisible(False)
        self.back_button.setEnabled(False)
        self.next_button.setEnabled(False)
        self.main_widget.setVisible(False)
        self.please_wait.setVisible(True)
        self.refresh_gui()
        return result

    def refresh_gui(self):
        # For some reason, to refresh the GUI this needs to be called twice
        self.app.processEvents()
        self.app.processEvents()

    def remove_from_recently_open(self, filename):
        self.config.remove_from_recently_open(filename)

    def text_input(self, title, message, is_valid, allow_multi=False):
        slayout = KeysLayout(parent=self, title=message, is_valid=is_valid,
                             allow_multi=allow_multi)
        self.exec_layout(slayout, title, next_enabled=False)
        return slayout.get_text()

    def seed_input(self, title, message, is_seed, options):
        slayout = SeedLayout(title=message, is_seed=is_seed, options=options, parent=self)
        self.exec_layout(slayout, title, next_enabled=False)
        return slayout.get_seed(), slayout.is_bip39, slayout.is_ext

    def bip38_prompt_for_pw(self, bip38_keys):
        ''' Reimplemented from basewizard superclass. Expected to return the pw
        dict or None. '''
        d = Bip38Importer(bip38_keys, parent=self.top_level_window())
        res = d.exec_()
        d.setParent(None)  # python GC quicker if this happens
        return d.decoded_keys  # dict will be empty if user cancelled

    @wizard_dialog
    def add_xpub_dialog(self, title, message, is_valid, run_next, allow_multi=False):
        return self.text_input(title, message, is_valid, allow_multi)

    @wizard_dialog
    def add_cosigner_dialog(self, run_next, index, is_valid):
        title = _("Add Cosigner") + " %d"%index
        message = ' '.join([
            _('Please enter the master public key (xpub) of your cosigner.'),
            _('Enter their master private key (xprv) if you want to be able to sign for them.')
        ])
        return self.text_input(title, message, is_valid)

    @wizard_dialog
    def restore_seed_dialog(self, run_next, test):
        options = []
        if self.opt_ext:
            options.append('ext')
        if self.opt_bip39:
            options.append('bip39')
        title = _('Enter Seed')
        message = _('Please enter your seed phrase in order to restore your wallet.')
        return self.seed_input(title, message, test, options)

    @wizard_dialog
    def confirm_seed_dialog(self, run_next, test):
        self.app.clipboard().clear()
        title = _('Confirm Seed')
        message = ' '.join([
            _('Your seed is important!'),
            _('If you lose your seed, your money will be permanently lost.'),
            _('To make sure that you have properly saved your seed, please retype it here.')
        ])
        seed, is_bip39, is_ext = self.seed_input(title, message, test, None)
        return seed

    @wizard_dialog
    def show_seed_dialog(self, run_next, seed_text):
        title =  _("Your wallet generation seed is:")
        slayout = SeedLayout(seed=seed_text, title=title, msg=True, options=['ext'])
        self.exec_layout(slayout)
        return slayout.is_ext

    def pw_layout(self, msg, kind):
        playout = PasswordLayout(None, msg, kind, self.next_button)
        playout.encrypt_cb.setChecked(True)
        self.exec_layout(playout.layout())
        return playout.new_password(), playout.encrypt_cb.isChecked()

    @wizard_dialog
    def request_password(self, run_next):
        """Request the user enter a new password and confirm it.  Return
        the password or None for no password."""
        return self.pw_layout(MSG_ENTER_PASSWORD, PW_NEW)

    def show_restore(self, wallet, network):
        # FIXME: these messages are shown after the install wizard is
        # finished and the window closed.  On MacOSX they appear parented
        # with a re-appeared ghost install wizard window...
        if network:
            def task():
                wallet.wait_until_synchronized()
                if wallet.is_found():
                    msg = _("Recovery successful")
                else:
                    msg = _("No transactions found for this seed")
                self.synchronized_signal.emit(msg)
            self.synchronized_signal.connect(self.show_message)
            t = threading.Thread(target = task)
            t.daemon = True
            t.start()
        else:
            msg = _("This wallet was restored offline. It may "
                    "contain more addresses than displayed.")
            self.show_message(msg)

    def _add_extra_button_to_layout(self, extra_button, layout):
        if (not isinstance(extra_button, (list, tuple))
                or not len(extra_button) == 2):
            return
        but_title, but_action = extra_button
        hbox = QHBoxLayout()
        hbox.setContentsMargins(12,24,12,12)
        but = QPushButton(but_title)
        hbox.addStretch(1)
        hbox.addWidget(but)
        layout.addLayout(hbox)
        but.clicked.connect(but_action)


    @wizard_dialog
    def confirm_dialog(self, title, message, run_next, extra_button=None):
        self.confirm(message, title, extra_button=extra_button)

    def confirm(self, message, title, extra_button=None):
        label = WWLabel(message)

        textInteractionFlags = (Qt.LinksAccessibleByMouse
                                | Qt.TextSelectableByMouse
                                | Qt.TextSelectableByKeyboard
                                | Qt.LinksAccessibleByKeyboard)
        label.setTextInteractionFlags(textInteractionFlags)
        label.setOpenExternalLinks(True)

        vbox = QVBoxLayout()
        vbox.addWidget(label)
        if extra_button:
            self._add_extra_button_to_layout(extra_button, vbox)
        self.exec_layout(vbox, title)

    @wizard_dialog
    def action_dialog(self, action, run_next):
        self.run(action)

    def terminate(self):
        self.accept_signal.emit()

    def waiting_dialog(self, task, msg):
        self.please_wait.setText(MSG_GENERATING_WAIT)
        self.refresh_gui()
        t = threading.Thread(target = task)
        t.start()
        t.join()

    @wizard_dialog
    def choice_dialog(self, title, message, choices, run_next, extra_button=None):
        c_values = [x[0] for x in choices]
        c_titles = [x[1] for x in choices]
        clayout = ChoicesLayout(message, c_titles)
        vbox = QVBoxLayout()
        vbox.addLayout(clayout.layout())
        if extra_button:
            self._add_extra_button_to_layout(extra_button, vbox)
        self.exec_layout(vbox, title)
        action = c_values[clayout.selected_index()]
        return action


    def query_choice(self, msg, choices):
        """called by hardware wallets"""
        clayout = ChoicesLayout(msg, choices)
        vbox = QVBoxLayout()
        vbox.addLayout(clayout.layout())
        self.exec_layout(vbox, '')
        return clayout.selected_index()

    @wizard_dialog
    def line_dialog(self, run_next, title, message, default, test, warning=''):
        vbox = QVBoxLayout()
        vbox.addWidget(WWLabel(message))
        line = QLineEdit()
        line.setText(default)
        def f(text):
            self.next_button.setEnabled(test(text))
        line.textEdited.connect(f)
        vbox.addWidget(line)
        vbox.addWidget(WWLabel(warning))
        self.exec_layout(vbox, title, next_enabled=test(default))
        return ' '.join(line.text().split())

    @wizard_dialog
    def show_xpub_dialog(self, xpub, run_next):
        msg = ' '.join([
            _("Here is your master public key."),
            _("Please share it with your cosigners.")
        ])
        vbox = QVBoxLayout()
        layout = SeedLayout(xpub, title=msg, icon=False)
        vbox.addLayout(layout.layout())
        self.exec_layout(vbox, _('Master Public Key'))
        return None

    def init_network(self, network):
        message = _("Electron Cash communicates with remote servers to get "
                  "information about your transactions and addresses. The "
                  "servers all fulfil the same purpose only differing in "
                  "hardware. In most cases you simply want to let Electron Cash "
                  "pick one at random.  However if you prefer feel free to "
                  "select a server manually.")
        choices = [_("Auto connect"), _("Select server manually")]
        title = _("How do you want to connect to a server? ")
        clayout = ChoicesLayout(message, choices)
        self.back_button.setText(_('Cancel'))
        self.exec_layout(clayout.layout(), title)
        r = clayout.selected_index()
        network.auto_connect = (r == 0)
        self.config.set_key('auto_connect', network.auto_connect, True)
        if r == 1:
            nlayout = NetworkChoiceLayout(self, network, self.config, wizard=True)
            if self.exec_layout(nlayout.layout()):
                nlayout.accept()

    @wizard_dialog
    def multisig_dialog(self, run_next):
        cw = CosignWidget(2, 2)
        m_edit = QSlider(Qt.Horizontal, self)
        n_edit = QSlider(Qt.Horizontal, self)
        n_edit.setMinimum(1)
        n_edit.setMaximum(15)
        m_edit.setMinimum(1)
        m_edit.setMaximum(2)
        n_edit.setValue(2)
        m_edit.setValue(2)
        n_label = QLabel()
        m_label = QLabel()
        grid = QGridLayout()
        grid.addWidget(n_label, 0, 0)
        grid.addWidget(n_edit, 0, 1)
        grid.addWidget(m_label, 1, 0)
        grid.addWidget(m_edit, 1, 1)
        def on_m(m):
            m_label.setText(_('Require %d signatures')%m)
            cw.set_m(m)
        def on_n(n):
            n_label.setText(_('From %d cosigners')%n)
            cw.set_n(n)
            m_edit.setMaximum(n)
        n_edit.valueChanged.connect(on_n)
        m_edit.valueChanged.connect(on_m)
        on_n(2)
        on_m(2)
        vbox = QVBoxLayout()
        vbox.addWidget(cw)
        vbox.addWidget(WWLabel(_("Choose the number of signatures needed to unlock funds in your wallet:")))
        vbox.addLayout(grid)
        self.exec_layout(vbox, _("Multi-Signature Wallet"))
        m = int(m_edit.value())
        n = int(n_edit.value())
        return (m, n)

    linux_hw_wallet_support_dialog = None
    def on_hw_wallet_support(self):
        ''' Overrides base wizard's noop impl. '''
        if sys.platform.startswith("linux"):
            if self.linux_hw_wallet_support_dialog:
                self.linux_hw_wallet_support_dialog.raise_()
                return
            # NB: this should only be imported from Linux
            from . import udev_installer
            self.linux_hw_wallet_support_dialog = udev_installer.InstallHardwareWalletSupportDialog(self.top_level_window(), self.plugins)
            self.linux_hw_wallet_support_dialog.exec_()
            self.linux_hw_wallet_support_dialog.setParent(None)
            self.linux_hw_wallet_support_dialog = None
        else:
            self.show_error("Linux only facility. FIXME!")