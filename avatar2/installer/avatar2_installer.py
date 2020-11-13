from __future__ import print_function
from distutils.spawn import find_executable as find
from os import system, chdir
from os.path import exists
from time import sleep
from shutil import rmtree
from curses import endwin as get_terminal_screen
from .config import *

import npyscreen as nps




# Strings used in varius menues
WELCOME_DIALOG = ('Welcome to the avatar2 target install system.\n\n'
                  'This installer will store settings into %s.\n'
                  'Please select \'ok\' if you agree.' % CONFIG_FILE)

ALLDONE_DIALOG = ('All requested targets are installed.\n'
                  'Returning to main menu')

ALR_INSTALL_WARN = ('It seems %s is already installed at %s\n'
                    'Are you sure you want to continue?') 

DIR_EXISTS_WARN = ('Installation directory %s exists.\n'
                   'Do you want to delete it?')

INSTALL_FAILED_ERR = ('Installation of %s failed!\n'
                      'Error: %s \n')

INSTALL_SUCCESS = ('Installation of %s succeeded!\n')


VERIFY_GIT_INSTALL = ('About to install target from git.\n'
                      'Please make sure the settings below are correct.')



MENTRY_GIT_INSTALL = 'Install via git'
MENTRY_APT_INSTALL = 'Install via apt-get'
MENTRY_CHANGE_PATH = 'Set path for installed binary'
MENTRY_CANCEL = 'Cancel'
MENTRY_BUILD = 'Build Target!'
MENTRY_FETCH_DEPS = 'Install dependencies via apt-get'






class AvatarInstallerMenu(nps.Form):
    EXTRA_KWARGS = []

    def __init__(self, *args, **keywords):
        self.next_form = keywords.get('next_form')
        self.action_on_ok = keywords.get('action_on_ok')

        [setattr(self, key, keywords.get(key)) for key in self.__class__.EXTRA_KWARGS]

        super(nps.Form, self).__init__(*args, **keywords)
        if self.name is None:
            self.name = 'avatar2 target installer'


class AvatarInstallerTargetMenu(AvatarInstallerMenu):

    def create(self):
        self.target_name = self.parentApp.current_target
        self.name = self.target_name + ' installer'
        options = []
        config = self.parentApp.config

        if TARGETS[self.target_name].get('git') is not None:
            options.append( MENTRY_GIT_INSTALL )

        if TARGETS[self.target_name].get('apt_name') is not None and \
           config.getboolean('DIST', 'has_apt') is True:
            options.append( MENTRY_APT_INSTALL )

        options.append( MENTRY_CHANGE_PATH )
        options.append( MENTRY_CANCEL)

        self.opt_form = self.add(nps.TitleSelectOne,
                                 name='What do you want to do?',
                                 values = options, value=[0,],
                                 scroll_on_exit=True
                                )

    def afterEditing(self):
        sel = self.opt_form.get_selected_objects()
        if len(sel) == 0:
            return
        sel = sel[0]

        if sel == MENTRY_CANCEL:
            self.parentApp.install_next_target()
        elif sel == MENTRY_APT_INSTALL:
            apt_name = TARGETS[self.target_name]['apt_name']
            if self.parentApp.apt_install(apt_name) is True:
                self.parentApp.setNextForm('InstallerSuccess')
            else:
                self.parentApp.setNextForm('InstallationFailed')

        elif sel == MENTRY_GIT_INSTALL:
            self.parentApp.setNextForm('GitInstaller')
        elif sel == MENTRY_CHANGE_PATH:
            self.parentApp.setNextForm('PathChanger')

class AvatarInstallerGitMenu(AvatarInstallerMenu):
    def create(self):
        self.target_name = self.parentApp.current_target
        self.name = self.target_name + ' git installer'

    
        self.form = self.add(nps.TitleText, name=VERIFY_GIT_INSTALL,
                             autowrap=True, editable=False)

        self.install_dir = self.parentApp.config.get(
            'DIST', 'default_install_path') + self.target_name

        self.git_path = self.add(nps.TitleText, name='Remote Repository',
                                value=TARGETS[self.target_name]['git'],
                                begin_entry_at=25)

        self.git_branch = self.add(nps.TitleText, name='Remote Branch',
                                   value='master', begin_entry_at=25)

        self.install_dir = self.add(nps.TitleFilename,
                                    name='Local directory',
                                    value=self.install_dir,
                                    begin_entry_at=25)
        
        conf = TARGETS[self.target_name].get('configure')
        self.configure_options = self.add(
             nps.TitleText, name='Configure options', begin_entry_at=25,
             value=conf, hidden=False if conf is not None else True
        )

        script = TARGETS[self.target_name].get('install_script')
        self.install_script = self.add(
                nps.TitleText, name='Install script (if used following parameters are ignored)',
                value=script, begin_entry_at=25,
                hidden=False if script is not None else True
        )

        make = TARGETS[self.target_name].get('make')
        self.make_options= self.add(
            nps.TitleText, name='Make options', begin_entry_at=25,
            value=make, hidden=False if make is not None else True
        )

        self.git_apt_deps = self.add(
                nps.TitleText, name='Dependencies with apt-get (default values for Ubuntu 20.04)',
                value=TARGETS[self.target_name]['git_apt_deps'],
                begin_entry_at=25
        )
           

        options = [MENTRY_BUILD, MENTRY_CANCEL]
        self.opt_form = self.add(nps.TitleSelectOne,
                                 name='What do you want to do?',
                                 values=options, value =[0,],
                                 scroll_on_exit=True)

    def afterEditing(self):
        sel = self.opt_form.get_selected_objects()
        if len(sel) == 0:
            return
        sel = sel[0]

        if sel == MENTRY_CANCEL:
            self.parentApp.setNextFormPrevious()
        if sel == MENTRY_BUILD:
            self.parentApp.install_dir = self.install_dir.value
            
            # save all the values in case we need to delete a dir
            self.parentApp.git_args = (self.install_dir.value,
                                       self.git_path.value,
                                       TARGETS[self.target_name]['install_cmd'])
            self.parentApp.git_kwargs = {
                'branch': self.git_branch.value,
                'apt_deps': self.git_apt_deps.value,
                'configure_options': self.configure_options.value,
                'make_options': self.make_options.value,
                'install_script': self.install_script.value
            }
            if exists(self.install_dir.value):
                self.parentApp.switchForm('DirExists')
                return
            # In the long run, we should aim for a seperated 'RunInstall'-form
            try:
                self.parentApp.git_install(*self.parentApp.git_args,
                                           **self.parentApp.git_kwargs)
                self.parentApp.setNextForm('InstallerSuccess')
            except Exception as e:
                self.parentApp.error = e
                self.parentApp.setNextForm('InstallationFailed')

class AvatarInstallerInstallError(nps.Popup,AvatarInstallerMenu):
    def create(self):
        self.text=INSTALL_FAILED_ERR % (self.parentApp.current_target,
                                        self.parentApp.error)
        self.add(nps.Pager, values=self.text.split('\n'),
                 autowrap=True, editable=False)

    def afterEditing(self):
        self.parentApp.setNextForm('TargetInstaller')


class AvatarInstallerInstallSuccess(nps.Popup,AvatarInstallerMenu):
    def create(self):
        self.text=INSTALL_SUCCESS % self.parentApp.current_target
        self.add(nps.Pager, values=self.text.split('\n'),
                 autowrap=True, editable=False)

    def afterEditing(self):
        self.parentApp.install_next_target()


class AvatarInstallerAF(nps.ActionFormV2, AvatarInstallerMenu):
    EXTRA_KWARGS = ['exit_on_cancel']

    def on_ok(self):
        if self.action_on_ok:
            res = self.action_on_ok()
        if self.next_form:
            self.parentApp.setNextForm(self.next_form)

    def on_cancel(self):
        if self.exit_on_cancel is True:
            exit()
        else:
            self.parentApp.setNextFormPrevious()


class AvatarInstallerUpdatePath(AvatarInstallerAF):

    def create(self):
        self.target_name = self.parentApp.current_target
        self.name = self.target_name + ' installer'
        self.install_dir = self.add(
            nps.TitleFilenameCombo,
            name='Choose new location:',
            value=self.parentApp.config.get('TARGETS', self.target_name)
        )

    def on_ok(self):
        self.parentApp.config.set('TARGETS', self.target_name,
                                  self.install_dir.value)
        self.parentApp.install_next_target()


class AvatarInstallerWarning(AvatarInstallerAF):
    EXTRA_KWARGS = AvatarInstallerAF.EXTRA_KWARGS + ['text']

    def create(self):
        self.add(nps.Pager, values=self.text.split('\n'),
                 autowrap=True, editable=False)
    
class AvatarInstallerWarningPopup(nps.ActionPopup, AvatarInstallerWarning):
    ''' Displays a warning as popup '''
    pass

class AvatarInstallerWarningAlreadyInstalled(AvatarInstallerWarningPopup):
    def create(self):
        path = self.parentApp.config.get_target_path(self.parentApp.current_target)
        self.name='WARNING!'
        self.text=ALR_INSTALL_WARN % (self.parentApp.current_target, path)
        super(AvatarInstallerWarningPopup, self).create()

class AvatarInstallerWarningDirExists(AvatarInstallerWarningPopup):
    def create(self):
        self.name='WARNING!'
        self.text= DIR_EXISTS_WARN % (self.parentApp.install_dir)
        super(AvatarInstallerWarningDirExists, self).create()


    def on_ok(self):
        self.parentApp.delete_dir()
        try:
            self.parentApp.git_install(*self.parentApp.git_args,
                                       **self.parentApp.git_kwargs)
            self.parentApp.setNextForm('InstallerSuccess')
        except Exception as e:
            self.parentApp.error = e
            self.parentApp.setNextForm('InstallationFailed')


class AvatarInstallerTargetSelector(AvatarInstallerAF):
    OK_BUTTON_BR_OFFSET = (2, 14)
    CANCEL_BUTTON_BR_OFFSET = (2, 6)
    OK_BUTTON_TEXT          = "OK"
    CANCEL_BUTTON_TEXT = "EXIT"

    def create(self):
        self.exit_on_cancel = True
        self.opt_form = self.add(
            nps.TitleMultiSelect,
            name='Which Targets do you want to install/modify?',
            values=list(TARGETS.keys()))

    def on_ok(self):
        self.parentApp.installer_list = self.opt_form.get_selected_objects()
        if self.parentApp.installer_list is not None:
            self.parentApp.current_target = self.parentApp.installer_list.pop()
            path = self.parentApp.config.get_target_path(self.parentApp.current_target)
            if path == None:
                self.parentApp.switchForm('TargetInstaller')
            else:
                self.parentApp.setNextForm('AlreadyInstalled')


class Avatar2Installer(nps.NPSAppManaged):
    '''
    The installer holds all the logic to install targets.
    It create the UI forms in its onStart method, all other functions
    are just callbacks called form the UI

    For dynamic content in windows, all neccessary information are saved
    in the AvatarInstaller object, which  also can be written by the forms.
    As a rule of thumb, forms should NOT save any data on their own.
    '''

    STARTING_FORM = 'WelcomeDialog'



    def install_next_target(self):
        self.config.write_config()
        if len( self.installer_list ) > 0:
            self.current_target = self.installer_list.pop()
            self.setNextForm('TargetInstaller')
        else:
            self.setNextForm('AllDone')

    def apt_install(self, package):
        get_terminal_screen()
        res = system('sudo apt-get install %s' % package)
        sleep(1.5)
        if res == 0:
            self.config.set('TARGETS', self.current_target, package)
            return True
        else:
            return False

    def git_install(self, local_directory, repository, install_commands,
                    branch='master', apt_deps=None, configure_options=None,
                    make_options=None, install_script=None):

        get_terminal_screen()

        if apt_deps != '':
            system('echo')
            system('echo [*] Installing dependencies...')
            res = system('sudo apt-get install %s' % apt_deps)
            sleep(1.5)
            if res != 0:
                raise Exception('Fail to install dependencies %s' % apt_deps)

        system('echo')
        system('echo [*] Installing from git...')
        git_exec = find('git')
        system('%s clone %s --single-branch --branch %s %s'  % 
               (git_exec, repository, branch, local_directory) )

        chdir(local_directory)

        if install_script is None or install_script.strip() == '':
            for cmd in install_commands:
                if cmd == './configure' and configure_options is not None:
                    res = system(cmd + ' ' + configure_options)
                elif cmd == 'make' and make_options is not None:
                    res = system(cmd + ' ' + make_options)
                else:
                    res = system(cmd)
                if res != 0:
                    sleep(2)
                    raise Exception('Executing install command \'%s\' failed' % cmd)

        else:
            res = system('echo ' + install_script + ' ' + configure_options)
            res = system(install_script + ' ' + configure_options)
            if res != 0:
                raise Exception('Install script %s failed' % install_script)

        exec_path = '%s/%s' % (self.install_dir,
                               TARGETS[self.current_target]['rel_path'])
        if exists(exec_path):
            self.config.set('TARGETS', self.current_target, exec_path)

    def delete_dir(self):
        rmtree(self.install_dir)
        
    def onStart(self):

        self.config = AvatarConfig()
        self.current_target = None
        self.install_dir = None
        self.addForm('WelcomeDialog', AvatarInstallerWarningPopup, 
                     text=WELCOME_DIALOG, exit_on_cancel=True,
                     next_form='TargetSelector',
                     action_on_ok=self.config.write_config)

        self.addForm('TargetSelector', AvatarInstallerTargetSelector,
                     next_form='AlreadyInstalled')

        # Forms with dynamically generated content require a formclass,
        # which will spawn a new FormInstance on every edit of the form
        self.addFormClass('AlreadyInstalled',
                          AvatarInstallerWarningAlreadyInstalled,
                          next_form='TargetInstaller')

        self.addFormClass('InstallationFailed', AvatarInstallerInstallError)
        self.addFormClass('TargetInstaller', AvatarInstallerTargetMenu)
        self.addFormClass('GitInstaller', AvatarInstallerGitMenu)
        self.addFormClass('DirExists', AvatarInstallerWarningDirExists,
                          action_on_exit=self.delete_dir)
        self.addFormClass('PathChanger', AvatarInstallerUpdatePath)
        self.addFormClass('InstallerSuccess', AvatarInstallerInstallSuccess)

        self.addForm('AllDone', AvatarInstallerWarningPopup, 
                     text=ALLDONE_DIALOG, exit_on_cancel=True,
                     next_form='TargetSelector')


if __name__ == '__main__':
   Avatar2Installer().run()
