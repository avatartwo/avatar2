from threading import Thread
from functools import wraps

watched_types = {
    'StateTransfer',
    'BreakpointHit',
    'UpdateState',
    'RemoteMemoryRead',
    'RemoteMemoryWrite',
    'AvatarGetStatus',
}

BEFORE = 'before'
AFTER  = 'after'

def watch(watched_type):
    """
    Decorator for the watchmen system
    """
    def decorator(func):
        @wraps(func)
        def watchtrigger(self, *args, **kwargs):
            self.watchmen.t(watched_type, BEFORE, *args, **kwargs)
            ret = func(self, *args, **kwargs)
            kwargs.update({'watched_return': ret})
            self.watchmen.t(watched_type, AFTER, *args, **kwargs)
            return ret
        return watchtrigger
    return decorator


class asyncReaction(Thread):
    def __init__(self, avatar, callback, *args, **kwargs):
        super(asyncReaction, self).__init__()
        self.avatar = avatar
        self.callback = callback
        self.args = args
        self.kwargs = kwargs
    def run(self):
        self.callback(self.avatar, *self.args, **self.kwargs)


class WatchedEvent(object):

    def __init__(self, type, when, callback, async, *args, **kwargs):
        self._callback = callback
        self.type = type
        self.when = when
        self.async = async

    def react(self, avatar, *args, **kwargs):
        if self._callback == None:
            raise Exception("No callback defined for watchmen of type %s" %
                            self.type)
        else:
            if self.async:
                thread = asyncReaction(avatar, self._callback, *args, **kwargs)
                thread.start()
            else:
                self._callback(avatar, *args, **kwargs)



class Watchmen(object):
    """
    """

    def __init__(self, avatar):
        self._watched_events = {}
        self._avatar = avatar
        self.watched_types = watched_types

        for e in self.watched_types: 
            self._watched_events[e] = []

    def add_watch_types(self, watched_types):
        self.watched_types.update(watched_types)
        for e in watched_types:
            self._watched_events[e] = []

    def add_watchman(self, type, when=BEFORE, callback=None, async=False, *args, **kwargs):

        if type not in self.watched_types:
            raise Exception("Requested event_type does not exist")
        if when not in (BEFORE, AFTER):
            raise Exception("Watchman has to be invoked \'before\' or \'after\'!")

        w = WatchedEvent(type, when, callback, async, *args, **kwargs)
        self._watched_events[type].append(w)
        return w

    add = add_watchman

    def remove_watchman(self, type, watchman):
        if type not in self.watched_types:
            raise Exception("Requested event_type does not exist")
        self._watched_events[type].remove(watchman)
    
    
    def trigger(self, type, when, *args, **kwargs):
        for watchman in self._watched_events[type]:
            if watchman.when == when:
                watchman.react(self._avatar, *args, **kwargs)

    t = trigger




