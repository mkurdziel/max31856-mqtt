#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import _thread
import board
import argparse
import busio
import os
import subprocess
import sys
import digitalio
import adafruit_max31856
import paho.mqtt.client as mqtt
import sdnotify
import time
import threading
import json

from tzlocal import get_localzone
from datetime import datetime, timedelta
from collections import OrderedDict
from unidecode import unidecode
from colorama import init as colorama_init
from colorama import Fore, Back, Style
from configparser import ConfigParser

script_version = "0.0.1"
script_name = 'max31856-mqtt'
script_info = '{} v{}'.format(script_name, script_version)
project_name = 'MAX31856 MQTT Reporter'
project_url = 'https://github.com/mkurdziel/max31856-mqtt'


# we'll use this throughout
local_tz = get_localzone()

if False:
    # will be caught by python 2.7 to be illegal syntax
    print_line('Sorry, this script requires a python3 runtime environment.', file=sys.stderr)
    os._exit(1)

# Argparse
opt_debug = False
opt_verbose = False

# Systemd Service Notifications - https://github.com/bb4242/sdnotify
sd_notifier = sdnotify.SystemdNotifier()

# create a spi object
spi = busio.SPI(board.SCK, board.MOSI, board.MISO)

# allocate a CS pin and set the direction
cs = digitalio.DigitalInOut(board.D5)
cs.direction = digitalio.Direction.OUTPUT

# create a thermocouple object with the above
thermocouple = adafruit_max31856.MAX31856(spi, cs, adafruit_max31856.ThermocoupleType.K)


# -----------------------------------------------------------------------------
#  Logging
# -----------------------------------------------------------------------------
def print_line(text, error=False, warning=False, info=False, verbose=False, debug=False, console=True, sd_notify=False):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    if console:
        if error:
            print(Fore.RED + Style.BRIGHT + '[{}] '.format(timestamp) + Style.RESET_ALL + '{}'.format(text) + Style.RESET_ALL, file=sys.stderr)
        elif warning:
            print(Fore.YELLOW + '[{}] '.format(timestamp) + Style.RESET_ALL + '{}'.format(text) + Style.RESET_ALL)
        elif info or verbose:
            if opt_verbose:
                print(Fore.GREEN + '[{}] '.format(timestamp) + Fore.YELLOW  + '- ' + '{}'.format(text) + Style.RESET_ALL)
        elif debug:
            if opt_debug:
                print(Fore.CYAN + '[{}] '.format(timestamp) + '- (DBG): ' + '{}'.format(text) + Style.RESET_ALL)
        else:
            print(Fore.GREEN + '[{}] '.format(timestamp) + Style.RESET_ALL + '{}'.format(text) + Style.RESET_ALL)

    timestamp_sd = time.strftime('%b %d %H:%M:%S', time.localtime())
    if sd_notify:
        sd_notifier.notify('STATUS={} - {}.'.format(timestamp_sd, unidecode(text)))


# Argparse
parser = argparse.ArgumentParser(description=project_name, epilog='For further details see: ' + project_url)
parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")
parser.add_argument("-d", "--debug", help="show debug output", action="store_true")
parser.add_argument("-s", "--stall", help="TEST: report only the first time", action="store_true")
parser.add_argument("-c", '--config_dir', help='set directory where config.ini is located', default=sys.path[0])
parse_args = parser.parse_args()

config_dir = parse_args.config_dir
opt_debug = parse_args.debug
opt_verbose = parse_args.verbose
opt_stall = parse_args.stall

print_line(script_info, info=True)
if opt_verbose:
    print_line('Verbose enabled', info=True)
if opt_debug:
    print_line('Debug enabled', debug=True)
if opt_stall:
    print_line('TEST: Stall (no-re-reporting) enabled', debug=True)


# -----------------------------------------------------------------------------
#  MQTT handlers
# -----------------------------------------------------------------------------
mqtt_client_connected = False
print_line('* init mqtt_client_connected=[{}]'.format(mqtt_client_connected), debug=True)
mqtt_client_should_attempt_reconnect = True

def on_connect(client, userdata, flags, rc):
    global mqtt_client_connected
    if rc == 0:
        print_line('* MQTT connection established', console=True, sd_notify=True)
        print_line('')  # blank line?!
        #_thread.start_new_thread(afterMQTTConnect, ())
        mqtt_client_connected = True
        print_line('on_connect() mqtt_client_connected=[{}]'.format(mqtt_client_connected), debug=True)
    else:
        print_line('! Connection error with result code {} - {}'.format(str(rc), mqtt.connack_string(rc)), error=True)
        print_line('MQTT Connection error with result code {} - {}'.format(str(rc), mqtt.connack_string(rc)), error=True, sd_notify=True)
        mqtt_client_connected = False   # technically NOT useful but readying possible new shape...
        print_line('on_connect() mqtt_client_connected=[{}]'.format(mqtt_client_connected), debug=True, error=True)
        #kill main thread
        os._exit(1)


def on_publish(client, userdata, mid):
    #print_line('* Data successfully published.')
    pass


# -----------------------------------------------------------------------------
#  Configuration
# -----------------------------------------------------------------------------
config = ConfigParser(delimiters=('=', ), inline_comment_prefixes=('#'))
config.optionxform = str
try:
    with open(os.path.join(config_dir, 'config.ini')) as config_file:
        config.read_file(config_file)
except IOError:
    print_line('No configuration file "config.ini"', error=True, sd_notify=True)
    sys.exit(1)

default_base_topic = 'home/nodes'
base_topic = config['MQTT'].get('base_topic', default_base_topic).lower()

default_sensor_name = 'max-31586-reporter'
sensor_name = config['MQTT'].get('sensor_name', default_sensor_name).lower()

# by default Home Assistant listens to the /homeassistant but it can be changed for a given installation
default_discovery_prefix = 'homeassistant'
discovery_prefix = config['MQTT'].get('discovery_prefix', default_discovery_prefix).lower()

# report our RPi values every 1min
min_interval_in_seconds = 10 
max_interval_in_seconds = 600
default_interval_in_seconds = 60
interval_in_seconds = config['Daemon'].getint('interval_in_seconds', default_interval_in_seconds)

# default domain when hostname -f doesn't return it
default_domain = ''
fallback_domain = config['Daemon'].get('fallback_domain', default_domain).lower()

# Check configuration
#
if (interval_in_seconds < min_interval_in_seconds) or (interval_in_seconds > max_interval_in_seconds):
    print_line('ERROR: Invalid "interval_in_seconds" found in configuration file: "config.ini"! Must be [{}-{}] Fix and try again... Aborting'.format(min_interval_in_seconds, max_interval_in_seconds), error=True, sd_notify=True)
    sys.exit(1)

### Ensure required values within sections of our config are present
if not config['MQTT']:
    print_line('ERROR: No MQTT settings found in configuration file "config.ini"! Fix and try again... Aborting', error=True, sd_notify=True)
    sys.exit(1)

print_line('Configuration accepted', console=False, sd_notify=True)

# -----------------------------------------------------------------------------
#  RPi variables monitored
# -----------------------------------------------------------------------------

rpi_fqdn = ''
rpi_model_raw = ''
rpi_model = ''
rpi_linux_release = ''
rpi_linux_version = ''
temperature = ''


def getTemperature():
    global temperature
    #temperature = (thermocouple.temperature * 9/5) + 32
    temperature = thermocouple.temperature
    # Print the value.
    print("Temperature: {0:0.3f}F".format(temperature))


def getDeviceModel():
    global rpi_model
    global rpi_model_raw
    global rpi_connections
    out = subprocess.Popen("/bin/cat /proc/device-tree/model | /bin/sed -e 's/\\x0//g'",
           shell=True,
           stdout=subprocess.PIPE,
           stderr=subprocess.STDOUT)
    stdout,_ = out.communicate()
    rpi_model_raw = stdout.decode('utf-8')
    # now reduce string length (just more compact, same info)
    rpi_model = rpi_model_raw.replace('Raspberry ', 'R').replace('i Model ', 'i 1 Model').replace('Rev ', 'r').replace(' Plus ', '+')

    # now decode interfaces
    rpi_connections = 'e,w,b' # default
    if 'Pi 3 ' in rpi_model:
        if ' A ' in rpi_model:
            rpi_connections = 'w,b'
        else:
            rpi_connections = 'e,w,b'
    elif 'Pi 2 ' in rpi_model:
        rpi_connections = 'e'
    elif 'Pi 1 ' in rpi_model:
        if ' A ' in rpi_model:
            rpi_connections = ''
        else:
            rpi_connections = 'e'

    print_line('rpi_model_raw=[{}]'.format(rpi_model_raw), debug=True)
    print_line('rpi_model=[{}]'.format(rpi_model), debug=True)
    print_line('rpi_connections=[{}]'.format(rpi_connections), debug=True)


def getLinuxRelease():
    global rpi_linux_release
    out = subprocess.Popen("/bin/cat /etc/apt/sources.list | /bin/egrep -v '#' | /usr/bin/awk '{ print $3 }' | /bin/grep . | /usr/bin/sort -u",
           shell=True,
           stdout=subprocess.PIPE,
           stderr=subprocess.STDOUT)
    stdout,_ = out.communicate()
    rpi_linux_release = stdout.decode('utf-8').rstrip()
    print_line('rpi_linux_release=[{}]'.format(rpi_linux_release), debug=True)

def getLinuxVersion():
    global rpi_linux_version
    out = subprocess.Popen("/bin/uname -r",
           shell=True,
           stdout=subprocess.PIPE,
           stderr=subprocess.STDOUT)
    stdout,_ = out.communicate()
    rpi_linux_version = stdout.decode('utf-8').rstrip()
    print_line('rpi_linux_version=[{}]'.format(rpi_linux_version), debug=True)


def getNetworkIFsUsingIP(ip_cmd):
    cmd_str = '{} link show | /bin/egrep -v "link" | /bin/egrep " eth| wlan"'.format(ip_cmd)
    out = subprocess.Popen(cmd_str,
           shell=True,
           stdout=subprocess.PIPE,
           stderr=subprocess.STDOUT)
    stdout,_ = out.communicate()
    lines = stdout.decode('utf-8').split("\n")
    interfaceNames = []
    line_count = len(lines)
    if line_count > 2:
        line_count = 2;
    if line_count == 0:
        print_line('ERROR no lines left by ip(8) filter!',error=True)
        sys.exit(1)

    for lineIdx in range(line_count):
        trimmedLine = lines[lineIdx].lstrip().rstrip()
        if len(trimmedLine) > 0:
            lineParts = trimmedLine.split()
            interfaceName = lineParts[1].replace(':', '')
            interfaceNames.append(interfaceName)

    print_line('interfaceNames=[{}]'.format(interfaceNames), debug=True)

    trimmedLines = []
    for interface in interfaceNames:
        lines = getSingleInterfaceDetails(interface)
        for currLine in lines:
            trimmedLines.append(currLine)

    loadNetworkIFDetailsFromLines(trimmedLines)


def loadNetworkIFDetailsFromLines(ifConfigLines):
    global rpi_interfaces
    global rpi_mac
       #
    # OLDER SYSTEMS
    #  eth0      Link encap:Ethernet  HWaddr b8:27:eb:c8:81:f2
    #    inet addr:192.168.100.41  Bcast:192.168.100.255  Mask:255.255.255.0
    #  wlan0     Link encap:Ethernet  HWaddr 00:0f:60:03:e6:dd
    # NEWER SYSTEMS
    #  The following means eth0 (wired is NOT connected, and WiFi is connected)
    #  eth0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
    #    ether b8:27:eb:1a:f3:bc  txqueuelen 1000  (Ethernet)
    #  wlan0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
    #    inet 192.168.100.189  netmask 255.255.255.0  broadcast 192.168.100.255
    #    ether b8:27:eb:4f:a6:e9  txqueuelen 1000  (Ethernet)
    #
    tmpInterfaces = []
    haveIF = False
    imterfc = ''
    rpi_mac = ''
    for currLine in ifConfigLines:
        lineParts = currLine.split()
        #print_line('- currLine=[{}]'.format(currLine), debug=True)
        #print_line('- lineParts=[{}]'.format(lineParts), debug=True)
        if len(lineParts) > 0:
            # skip interfaces generated by Home Assistant on RPi
            if 'docker' in currLine or 'veth' in currLine or 'hassio' in currLine:
                haveIF = False
                continue
            # let's evaluate remaining interfaces
            if 'flags' in currLine:  # NEWER ONLY
                haveIF = True
                imterfc = lineParts[0].replace(':', '')
                #print_line('newIF=[{}]'.format(imterfc), debug=True)
            elif 'Link' in currLine:  # OLDER ONLY
                haveIF = True
                imterfc = lineParts[0].replace(':', '')
                newTuple = (imterfc, 'mac', lineParts[4])
                if rpi_mac == '':
                    rpi_mac = lineParts[4]
                    print_line('rpi_mac=[{}]'.format(rpi_mac), debug=True)
                tmpInterfaces.append(newTuple)
                print_line('newTuple=[{}]'.format(newTuple), debug=True)
            elif haveIF == True:
                print_line('IF=[{}], lineParts=[{}]'.format(imterfc, lineParts), debug=True)
                if 'inet' in currLine:  # OLDER & NEWER
                    newTuple = (imterfc, 'IP', lineParts[1].replace('addr:',''))
                    tmpInterfaces.append(newTuple)
                    print_line('newTuple=[{}]'.format(newTuple), debug=True)
                elif 'ether' in currLine: # NEWER ONLY
                    newTuple = (imterfc, 'mac', lineParts[1])
                    tmpInterfaces.append(newTuple)
                    if rpi_mac == '':
                        rpi_mac = lineParts[1]
                        print_line('rpi_mac=[{}]'.format(rpi_mac), debug=True)
                    print_line('newTuple=[{}]'.format(newTuple), debug=True)
                    haveIF = False

    rpi_interfaces = tmpInterfaces
    print_line('rpi_interfaces=[{}]'.format(rpi_interfaces), debug=True)
    print_line('rpi_mac=[{}]'.format(rpi_mac), debug=True)


def getSingleInterfaceDetails(interfaceName):
    cmdString = '/sbin/ifconfig {} | /bin/egrep "Link|flags|inet |ether " | /bin/egrep -v -i "lo:|loopback|inet6|\:\:1|127\.0\.0\.1"'.format(interfaceName)
    out = subprocess.Popen(cmdString,
           shell=True,
           stdout=subprocess.PIPE,
           stderr=subprocess.STDOUT)
    stdout,_ = out.communicate()
    lines = stdout.decode('utf-8').split("\n")
    trimmedLines = []
    for currLine in lines:
        trimmedLine = currLine.lstrip().rstrip()
        if len(trimmedLine) > 0:
            trimmedLines.append(trimmedLine)

    #print_line('interface:[{}] trimmedLines=[{}]'.format(interfaceName, trimmedLines), debug=True)
    return trimmedLines


def getIPCmd():
    cmd_locn1 = '/bin/ip'
    cmd_locn2 = '/sbin/ip'
    desiredCommand = ''
    if os.path.exists(cmd_locn1) == True:
        desiredCommand = cmd_locn1
    elif os.path.exists(cmd_locn2) == True:
        desiredCommand = cmd_locn2
    if desiredCommand != '':
        print_line('Found IP(8)=[{}]'.format(desiredCommand), debug=True)
    return desiredCommand



def getNetworkIFs():
    ip_cmd = getIPCmd()
    if ip_cmd != '':
        getNetworkIFsUsingIP(ip_cmd)
    else:
        out = subprocess.Popen('/sbin/ifconfig | /bin/egrep "Link|flags|inet |ether " | /bin/egrep -v -i "lo:|loopback|inet6|\:\:1|127\.0\.0\.1"',
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)
        stdout,_ = out.communicate()
        lines = stdout.decode('utf-8').split("\n")
        trimmedLines = []
        for currLine in lines:
            trimmedLine = currLine.lstrip().rstrip()
            if len(trimmedLine) > 0:
                trimmedLines.append(trimmedLine)

        print_line('trimmedLines=[{}]'.format(trimmedLines), debug=True)

        loadNetworkIFDetailsFromLines(trimmedLines)


def getHostnames():
    global rpi_hostname
    global rpi_fqdn
    out = subprocess.Popen("/bin/hostname -f",
           shell=True,
           stdout=subprocess.PIPE,
           stderr=subprocess.STDOUT)
    stdout,_ = out.communicate()
    fqdn_raw = stdout.decode('utf-8').rstrip()
    print_line('fqdn_raw=[{}]'.format(fqdn_raw), debug=True)
    rpi_hostname = fqdn_raw
    if '.' in fqdn_raw:
        # have good fqdn
        nameParts = fqdn_raw.split('.')
        rpi_fqdn = fqdn_raw
        rpi_hostname = nameParts[0]
    else:
        # missing domain, if we have a fallback apply it
        if len(fallback_domain) > 0:
            rpi_fqdn = '{}.{}'.format(fqdn_raw, fallback_domain)
        else:
            rpi_fqdn = rpi_hostname

    print_line('rpi_fqdn=[{}]'.format(rpi_fqdn), debug=True)
    print_line('rpi_hostname=[{}]'.format(rpi_hostname), debug=True)


# get our hostnames so we can setup MQTT
getHostnames()
if(sensor_name == default_sensor_name):
    sensor_name = 'rpi-{}'.format(rpi_hostname)

getDeviceModel()
getLinuxRelease()
getLinuxVersion()

# -----------------------------------------------------------------------------
#  timer and timer funcs for ALIVE MQTT Notices handling
# -----------------------------------------------------------------------------

ALIVE_TIMOUT_IN_SECONDS = 60

def publishAliveStatus():
    print_line('- SEND: yes, still alive -', debug=True)
    mqtt_client.publish(lwt_topic, payload=lwt_online_val, retain=False)

def aliveTimeoutHandler():
    print_line('- MQTT TIMER INTERRUPT -', debug=True)
    _thread.start_new_thread(publishAliveStatus, ())
    startAliveTimer()

def startAliveTimer():
    global aliveTimer
    global aliveTimerRunningStatus
    stopAliveTimer()
    aliveTimer = threading.Timer(ALIVE_TIMOUT_IN_SECONDS, aliveTimeoutHandler)
    aliveTimer.start()
    aliveTimerRunningStatus = True
    print_line('- started MQTT timer - every {} seconds'.format(ALIVE_TIMOUT_IN_SECONDS), debug=True)

def stopAliveTimer():
    global aliveTimer
    global aliveTimerRunningStatus
    aliveTimer.cancel()
    aliveTimerRunningStatus = False
    print_line('- stopped MQTT timer', debug=True)

def isAliveTimerRunning():
    global aliveTimerRunningStatus
    return aliveTimerRunningStatus

# our ALIVE TIMER
aliveTimer = threading.Timer(ALIVE_TIMOUT_IN_SECONDS, aliveTimeoutHandler)
# our BOOL tracking state of ALIVE TIMER
aliveTimerRunningStatus = False



# -----------------------------------------------------------------------------
#  MQTT setup and startup
# -----------------------------------------------------------------------------

# MQTT connection
lwt_topic = '{}/sensor/{}/status'.format(base_topic, sensor_name.lower())
lwt_online_val = 'online'
lwt_offline_val = 'offline'

print_line('Connecting to MQTT broker ...', verbose=True)
mqtt_client = mqtt.Client()
mqtt_client.on_connect = on_connect
mqtt_client.on_publish = on_publish



mqtt_client.will_set(lwt_topic, payload=lwt_offline_val, retain=True)

if config['MQTT'].getboolean('tls', False):
    # According to the docs, setting PROTOCOL_SSLv23 "Selects the highest protocol version
    # that both the client and server support. Despite the name, this option can select
    # “TLS” protocols as well as “SSL”" - so this seems like a resonable default
    mqtt_client.tls_set(
        ca_certs=config['MQTT'].get('tls_ca_cert', None),
        keyfile=config['MQTT'].get('tls_keyfile', None),
        certfile=config['MQTT'].get('tls_certfile', None),
        tls_version=ssl.PROTOCOL_SSLv23
    )

mqtt_username = os.environ.get("MQTT_USERNAME", config['MQTT'].get('username'))
mqtt_password = os.environ.get("MQTT_PASSWORD", config['MQTT'].get('password', None))

if mqtt_username:
    mqtt_client.username_pw_set(mqtt_username, mqtt_password)
try:
    mqtt_client.connect(os.environ.get('MQTT_HOSTNAME', config['MQTT'].get('hostname', 'localhost')),
                        port=int(os.environ.get('MQTT_PORT', config['MQTT'].get('port', '1883'))),
                        keepalive=config['MQTT'].getint('keepalive', 60))
except:
    print_line('MQTT connection error. Please check your settings in the configuration file "config.ini"', error=True, sd_notify=True)
    sys.exit(1)
else:
    mqtt_client.publish(lwt_topic, payload=lwt_online_val, retain=False)
    mqtt_client.loop_start()

    while mqtt_client_connected == False: #wait in loop
        print_line('* Wait on mqtt_client_connected=[{}]'.format(mqtt_client_connected), debug=True)
        time.sleep(1.0) # some slack to establish the connection

    startAliveTimer()

sd_notifier.notify('READY=1')


# -----------------------------------------------------------------------------
#  Perform our MQTT Discovery Announcement...
# -----------------------------------------------------------------------------

# what RPi device are we on?
# get our hostnames so we can setup MQTT
getNetworkIFs() # this will fill-in rpi_mac

mac_basic = rpi_mac.lower().replace(":", "")
mac_left = mac_basic[:6]
mac_right = mac_basic[6:]
print_line('mac lt=[{}], rt=[{}], mac=[{}]'.format(mac_left, mac_right, mac_basic), debug=True)
uniqID = "RPi-{}Mon{}".format(mac_left, mac_right)

# our RPi Reporter device
LD_MONITOR = "monitor" # KeyError: 'home310/sensor/rpi-pi3plus/values' let's not use this 'values' as topic
LD_SYS_TEMP= "temperature"
LDS_PAYLOAD_NAME = "info"

# Publish our MQTT auto discovery
#  table of key items to publish:
detectorValues = OrderedDict([
    (LD_SYS_TEMP, dict(title="{}".format(sensor_name), device_class="temperature", no_title_prefix="yes", unit="°C", json_value="temperature_c", icon='mdi:thermometer', device_ident="max31856-{}".format(rpi_fqdn))),
])

print_line('Announcing RPi Monitoring device to MQTT broker for auto-discovery ...')

base_topic = '{}/sensor/{}'.format(base_topic, sensor_name.lower())
values_topic_rel = '{}/{}'.format('~', LD_MONITOR)
values_topic = '{}/{}'.format(base_topic, LD_MONITOR)
activity_topic_rel = '{}/status'.format('~')     # vs. LWT
activity_topic = '{}/status'.format(base_topic)    # vs. LWT

command_topic_rel = '~/set'

for [sensor, params] in detectorValues.items():
    discovery_topic = '{}/sensor/{}/{}/config'.format(discovery_prefix, sensor_name.lower(), sensor)
    payload = OrderedDict()
    if 'no_title_prefix' in params:
        payload['name'] = "{}".format(params['title'].title())
    else:
        payload['name'] = "{} {}".format(sensor_name.title(), params['title'].title())
    payload['uniq_id'] = "{}_{}".format(uniqID, sensor.lower())
    if 'device_class' in params:
        payload['dev_cla'] = params['device_class']
    if 'unit' in params:
        payload['unit_of_measurement'] = params['unit']
    if 'json_value' in params:
        payload['stat_t'] = values_topic_rel
        payload['val_tpl'] = "{{{{ value_json.{}.{} }}}}".format(LDS_PAYLOAD_NAME, params['json_value'])
    payload['~'] = base_topic
    payload['pl_avail'] = lwt_online_val
    payload['pl_not_avail'] = lwt_offline_val
    if 'icon' in params:
        payload['ic'] = params['icon']
    payload['avty_t'] = activity_topic_rel
    if 'json_attr' in params:
        payload['json_attr_t'] = values_topic_rel
        payload['json_attr_tpl'] = '{{{{ value_json.{} | tojson }}}}'.format(LDS_PAYLOAD_NAME)
    if 'device_ident' in params:
        payload['dev'] = {
                'identifiers' : ["{}".format(uniqID)],
                'manufacturer' : 'Raspberry Pi (Trading) Ltd.',
                'name' : params['device_ident'],
                'model' : '{}'.format(rpi_model),
                'sw_version': "{} {}".format(rpi_linux_release, rpi_linux_version)
        }
    else:
         payload['dev'] = {
                'identifiers' : ["{}".format(uniqID)],
         }
    mqtt_client.publish(discovery_topic, json.dumps(payload), 1, retain=True)

    # remove connections as test:                  'connections' : [["mac", mac.lower()], [interface, ipaddr]],

# -----------------------------------------------------------------------------
#  timer and timer funcs for period handling
# -----------------------------------------------------------------------------

TIMER_INTERRUPT = (-1)
TEST_INTERRUPT = (-2)

def periodTimeoutHandler():
    print_line('- PERIOD TIMER INTERRUPT -', debug=True)
    handle_interrupt(TIMER_INTERRUPT) # '0' means we have a timer interrupt!!!
    startPeriodTimer()

def startPeriodTimer():
    global endPeriodTimer
    global periodTimeRunningStatus
    stopPeriodTimer()
    endPeriodTimer = threading.Timer(interval_in_seconds, periodTimeoutHandler)
    endPeriodTimer.start()
    periodTimeRunningStatus = True
    print_line('- started PERIOD timer - every {} seconds'.format(interval_in_seconds), debug=True)

def stopPeriodTimer():
    global endPeriodTimer
    global periodTimeRunningStatus
    endPeriodTimer.cancel()
    periodTimeRunningStatus = False
    print_line('- stopped PERIOD timer', debug=True)

def isPeriodTimerRunning():
    global periodTimeRunningStatus
    return periodTimeRunningStatus

# our TIMER
endPeriodTimer = threading.Timer(interval_in_seconds, periodTimeoutHandler)
# our BOOL tracking state of TIMER
periodTimeRunningStatus = False
reported_first_time = False


# -----------------------------------------------------------------------------
#  MQTT Transmit Helper Routines
# -----------------------------------------------------------------------------
SCRIPT_TIMESTAMP = "timestamp"
RPI_TEMPERATURE = "temperature_c"
SCRIPT_REPORT_INTERVAL = "report_interval"

def send_status(timestamp, nothing):
    rpiData = OrderedDict()
    rpiData[SCRIPT_TIMESTAMP] = timestamp.astimezone().replace(microsecond=0).isoformat()
    rpiData[RPI_TEMPERATURE] = temperature

    rpiTopDict = OrderedDict()
    rpiTopDict[LDS_PAYLOAD_NAME] = rpiData

    _thread.start_new_thread(publishMonitorData, (rpiTopDict, values_topic))


def publishMonitorData(latestData, topic):
    print_line('Publishing to MQTT topic "{}, Data:{}"'.format(topic, json.dumps(latestData)))
    mqtt_client.publish('{}'.format(topic), json.dumps(latestData), 1, retain=False)
    time.sleep(0.5) # some slack for the publish roundtrip and callback function


def update_values():
    # nothing here yet
    getTemperature()




# -----------------------------------------------------------------------------
# Interrupt handler
# -----------------------------------------------------------------------------
def handle_interrupt(channel):
    global reported_first_time
    sourceID = "<< INTR(" + str(channel) + ")"
    current_timestamp = datetime.now(local_tz)
    print_line(sourceID + " >> Time to report! (%s)" % current_timestamp.strftime('%H:%M:%S - %Y/%m/%d'), verbose=True)
    # ----------------------------------
    # have PERIOD interrupt!
    update_values()

    if (opt_stall == False or reported_first_time == False and opt_stall == True):
        # ok, report our new detection to MQTT
        _thread.start_new_thread(send_status, (current_timestamp, ''))
        reported_first_time = True
    else:
        print_line(sourceID + " >> Time to report! (%s) but SKIPPED (TEST: stall)" % current_timestamp.strftime('%H:%M:%S - %Y/%m/%d'), verbose=True)

def afterMQTTConnect():
    print_line('* afterMQTTConnect()', verbose=True)
    #  NOTE: this is run after MQTT connects
    # start our interval timer
    startPeriodTimer()
    # do our first report
    handle_interrupt(0)

# TESTING AGAIN
#getNetworkIFs()
#getLastUpdateDate()

# TESTING, early abort
#stopAliveTimer()
#exit(0)

afterMQTTConnect()  # now instead of after?

# now just hang in forever loop until script is stopped externally
try:
    while True:
        #  our INTERVAL timer does the work
        time.sleep(10000)

finally:
    # cleanup used pins... just because we like cleaning up after us
    stopPeriodTimer()   # don't leave our timers running!
    stopAliveTimer()

