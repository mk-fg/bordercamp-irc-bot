bordercamp-irc-bot
--------------------

Helper bot for real-time even notification over IRC (Internet Relay Chat).

Rationale is simple - being an IRC addict, I already have proper real-time
rate-limited, filtered and properly buffered/logged notificatons set up for IRC
events, so there's no need to re-invent the wheel for occasional system
notifications - just dump these into monitored IRC channel and let
[ZNC](http://znc.in)/client/[notification-daemon](https://github.com/mk-fg/notification-thing)
do the rest.

Bot code isn't that straightforward though, as I plan to extend it to perform
lots of miscellaneous monitoring and querying chores, so it's more of a
framework with centralized (extenisble) configuration system and pluggable
modules (via [distutils entry
points](http://packages.python.org/distribute/setuptools.html?highlight=entry%20points#dynamic-discovery-of-services-and-plugins)).

See the [base configuration
file](https://github.com/mk-fg/bordercamp-irc-bot/blob/master/bordercamp/core.yaml)
for the up-to-date overview of available stuff.
