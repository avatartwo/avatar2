from threading import Thread
from functools import wraps


class WatchedTypes(object):
    watched_types = [
        'StateTransfer',
        'BreakpointHit',
        'UpdateState',
        'SyscallCatched',
        'RemoteMemoryRead',
        'RemoteMemoryWrite',
        'RemoteInterruptEnter',
        'RemoteInterruptExit',
        'AvatarGetStatus',
        'AddTarget',
        'TargetInit',
        'TargetShutdown',
        'TargetCont',
        'TargetStop',
        'TargetStep',
        'TargetGetSymbol',
        'TargetWriteMemory',
        'TargetReadMemory',
        'TargetRegisterWrite',
        'TargetRegisterRead',
        'TargetSetBreakpoint',
        'TargetSetWatchPoint',
        'TargetRemovebreakpoint',
        'TargetWait',
        'TargetSetFile',
        'TargetDownload',
        'TargetInjectInterrupt'
    ]

    def __init__(self):
        self.watched_types = []
        for type in WatchedTypes.watched_types:
            setattr(self, type, type)
            self.watched_types.append(type)

    def __iter__(self):
        for type in self.watched_types:
            yield type

    def _add(self, type):
        if type not in self.watched_types:
            self.watched_types.append(type)
            setattr(self, type, type)
            return True
        return False


BEFORE = 'before'
AFTER = 'after'


def watch(watched_type):
    """
    Decorator for the watchmen system
    """

    def decorator(func):
        @wraps(func)
        def watchtrigger(self, *args, **kwargs):
            # To avoid circular dependencies, we import here ...
            from .avatar2 import Avatar
            from .targets.target import Target

            cb_kwargs = dict(kwargs)
            if isinstance(self, Avatar):
                avatar = self
            elif isinstance(self, Target):
                avatar = self.avatar
                cb_kwargs['watched_target'] = self

            avatar.watchmen.t(watched_type, BEFORE, *args, **cb_kwargs)
            ret = func(self, *args, **kwargs)
            cb_kwargs.update({'watched_return': ret})
            cb_ret = avatar.watchmen.t(watched_type, AFTER, *args, **cb_kwargs)

            return ret if cb_ret is None else cb_ret

        return watchtrigger

    return decorator


class AsyncReaction(Thread):
    def __init__(self, avatar, callback, *args, **kwargs):
        super(AsyncReaction, self).__init__()
        self.avatar = avatar
        self.callback = callback
        self.args = args
        self.kwargs = kwargs

    def run(self):
        self.callback(self.avatar, *self.args, **self.kwargs)


class WatchedEvent(object):
    # noinspection PyUnusedLocal
    def __init__(self, watch_type, when, callback, is_async,
                 overwrite_return = False, *args, **kwargs):
        self._callback = callback
        self.type = watch_type
        self.when = when
        self.is_async = is_async
        self.overwrite_return = overwrite_return
        self.watchmen_args = args
        self.watchmen_kwargs = kwargs

    def react(self, avatar, *args, **kwargs):
        if self._callback is None:
            raise Exception("No callback defined for watchmen of type %s" %
                            self.type)
        else:
            args += self.watchmen_args
            # WARNING: This could overwrite original kwargs,
            #          which may be desired in some cases
            kwargs.update(self.watchmen_kwargs)
            if self.is_async:
                thread = AsyncReaction(avatar, self._callback, *args, **kwargs)
                self.daemon = True
                thread.start()
            else:
                ret = self._callback(avatar, *args, **kwargs)
                if self.overwrite_return:
                    return ret
                


class Watchmen(object):
    """
    """

    def __init__(self, avatar):
        self._watched_events = {}
        self._avatar = avatar
        self.watched_types = WatchedTypes()

        for e in self.watched_types:
            self._watched_events[e] = []

    def add_watch_types(self, watched_types):
        for type in watched_types:
            if self.watched_types._add(type):
                self._watched_events[type] = []

    def add_watchman(self, watch_type, when=BEFORE, callback=None, is_async=False, overwrite_return=False, *args, **kwargs):

        if watch_type not in self.watched_types:
            raise Exception("Requested event_type does not exist")
        if when not in (BEFORE, AFTER):
            raise Exception("Watchman has to be invoked \'before\' or \'after\'!")
        if when == BEFORE and overwrite_return == True:
            self._avatar.log.warning("Overite return enabled for watchman BEFORE event %s. Discarding." % watch_type)
            overwrite_return = False
        w = WatchedEvent(watch_type, when, callback, is_async,
                         overwrite_return=overwrite_return,
                         *args, **kwargs)
        overwriting_cbs = [x.overwrite_return for x in
                           self._watched_events[watch_type]
                           if x.overwrite_return]

        if len(overwriting_cbs) > 1:
            self._avatar.log.warning("More than one watchman can modify the return value for the event. Watch type: %s" % watch_type)
        self._watched_events[watch_type].append(w)
        return w

    add = add_watchman

    def remove_watchman(self, watch_type, watchman):
        if watch_type not in self.watched_types:
            raise Exception("Requested event_type does not exist")
        self._watched_events[watch_type].remove(watchman)

    def trigger(self, watch_type, when, *args, **kwargs):
        ret = None
        for watchman in self._watched_events[watch_type]:
            if watchman.when == when:
                if watchman.overwrite_return:
                    ret = watchman.react(self._avatar, *args, **kwargs)
                    kwargs.update({'watched_return': ret})
                else:
                    watchman.react(self._avatar, *args, **kwargs)
        return ret

    t = trigger
