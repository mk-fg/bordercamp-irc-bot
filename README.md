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



Installation
--------------------

It's a regular package for Python 2.7 (not 3.X), but not in pypi, so can be
installed from a checkout with something like that:

	% python setup.py install

Better way would be to use [pip](http://pip-installer.org/) to install all the
necessary dependencies as well:

	% pip install 'git+https://github.com/mk-fg/bordercamp-irc-bot.git#egg=bordercamp-irc-bot'

Note that to install stuff in system-wide PATH and site-packages, elevated
privileges are often required.
Use "install --user",
[~/.pydistutils.cfg](http://docs.python.org/install/index.html#distutils-configuration-files)
or [virtualenv](http://pypi.python.org/pypi/virtualenv) to do unprivileged
installs into custom paths.

Alternatively, `./bordercamp-irc-bot` can be run right from the checkout tree
without any installation.

### Requirements

* Python 2.7 (not 3.X)
* [layered-yaml-attrdict-config](https://github.com/mk-fg/layered-yaml-attrdict-config)
* [Twisted](http://twistedmatrix.com/) (core, words)
* (optional) [xattr](https://pypi.python.org/pypi/xattr/) for reliable log-position tracking



Usage
--------------------

All the relevant stuff should be in the [configuration
file](https://github.com/mk-fg/bordercamp-irc-bot/blob/master/bordercamp-irc-bot/core.yaml).

Since several configuration files can be specified (each later one overidding
corresponding values in the former), it's recommended never to touch the shipped
original file (which gets read automatically) and just create a simplier config,
overriding what's necessary.

Below are relevant configuration snippets.


### Connection / server

It's the primary parameters, and defined in to "core" section.

First order of business is the connection to the IRC server:

	core:
		connection:
			endpoint: tcp:host=localhost:port=6667

Connection endpoint is specified as twisted endpoint, see [the
docs](http://twistedmatrix.com/documents/current/api/twisted.internet.endpoints.html#clientFromString)
for format specs, it's all fairly straightforward.
SSL connections are supported as well.

Actual bot-user parameters (like nick and password) are [described
here](http://twistedmatrix.com/documents/current/api/twisted.words.protocols.irc.IRCClient.html):

		nickname: bot
		realname: bordercamp bot
		# username:
		# password:
		# userinfo:

In case there's no convenient private IRC server available, bot can actually
start a local server:

		server:
			endpoint: tcp:6667:interface=localhost
			passwd:
				alice: secretpassword

Listening socket is defined in the same way as with the connection, as a
[twisted endpoint](http://twistedmatrix.com/documents/current/api/twisted.internet.endpoints.html#serverFromString).
Client endpoint is still relevant, since client connects to a local server same
way as the other clients do, so if it needs to connect to it's own host, point
it to the same interface/port where the server was created.

passwd is a "login: password" pairs, in the above example access (aside from bot
itself) is allowed for user "alice".


### Modules

Defined in the corresponding config section and can be of one of three types:

* "relay" - represents python entry_point module. It's basically just an object
  that can receive and/or send messages, without much control as to from where
  it gets it and where it sends them to. Examples are "logtail" relay which
  reads the lines from logs or "pipe_sub" relay, which does regexp substitution
  on the received line. Implementation is just a class with a "dispatch" method.

* "channel" - IRC channel. Basically the same as relay, as it can receive
  messages (which then get sent to server, into the channel), or "send" the
  messages it received from the corresponding channel.

* "route" - module that ties any number of "channel" and "relay" modules
  together. Basically just specifies which modules should messages be taken from
  and which modules should get them.

Simple-case, "logtail" module reads the messages into the "#bordercamp" IRC
channel:

	logtail:
		type: relay
		monitor: '/var/log/{messages,*.log}'

	bordercamp:
		type: channel
		name: '#bordercamp'

	log_report:
		type: route
		src: logtail
		dst: bordercamp

Same thing, but with some IP->hostname resolution and regexp-replacement along
the way:

	logtail:
		type: relay
		monitor: '/var/log/{messages,*.log}'

	pipe_syslog_clean:
		type: relay
		name: pipe_sub
		src: '\d{4}-\d{2}-\d{2}T(\d{2}:){2}\d{2}\+\d{2}:\d{2} (?P<channel>[\w.]+)<\d+> (?P<msg>.*)'
		dst: '\g<channel> \g<msg>'
	pipe_syslog_resolve:
		type: relay
		name: pipe_resolve
		addr: '^[\w.]+ .*?\[(\d+|-)\]@(?P<addr>\S+): '

	bordercamp:
		type: channel
		name: '#bordercamp'

	log_report:
		type: route
		src: logtail
		dst: bordercamp
		pipe: [pipe_syslog_clean, pipe_syslog_resolve]

Note that relay "name" corresponds to entry point module name, in case of
"logtail", relay name is used, because it's omitted.

[Baseline configuration
file](https://github.com/mk-fg/bordercamp-irc-bot/blob/master/bordercamp/core.yaml)
should contain more details and up-to-date examples.
