# Copyright (c) 2024, Ben Gruver
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import argparse
import asyncio
import contextlib
import logging
import re

from bleak import BLEDevice, AdvertisementData, BleakScanner

import wyze_scale_tool
from wyze_scale_tool.wyze_scale import WyzeScaleProtocol, WyzeScale

_LOGGER = logging.getLogger("wyze_scale")


async def scan_for_scale(multiple=False):

    found_devices = set()
    result_queue = asyncio.Queue()

    def callback(device: BLEDevice, advertising_data: AdvertisementData):
        if advertising_data.local_name and advertising_data.local_name != "WL_SC3":
            _LOGGER.warning('Unexpected local name: "%s", expecting "WL_SC3"' % advertising_data.local_name)
        if not advertising_data.manufacturer_data:
            _LOGGER.warning('No manufacturer data in advertisement.')
        if len(advertising_data.manufacturer_data) != 1:
            _LOGGER.warning("unexpected items in manufacturer data")
        if 0x870 not in advertising_data.manufacturer_data:
            _LOGGER.warning("manufacturer data does not contain expected key: 0x0870")
        if advertising_data.manufacturer_data[0x870][0:2] != b'\x07\x02':
            _LOGGER.warning("The first bytes of manufacturer data[0x0870] are not 0x0702 as expected.")
        if device.address not in found_devices:
            found_devices.add(device.address)
            result_queue.put_nowait((device, advertising_data))

    async with BleakScanner(
            detection_callback=callback,
            service_uuids=[WyzeScaleProtocol.SERVICE]):
        while True:
            yield await result_queue.get()
            if not multiple:
                break


async def scan(args):
    async def do_scan():
        async for (device, ad_data) in scan_for_scale(multiple=args.multiple):
            print(device.address)

    with contextlib.suppress(asyncio.TimeoutError):
        await asyncio.wait_for(do_scan(), args.scan_time)


async def _scan_for_first_scale(timeout):
    _LOGGER.info("Scanning for scale")

    async def do_scan():
        async for (device, ad_data) in scan_for_scale(multiple=False):
            return device.address

    with contextlib.suppress(asyncio.TimeoutError):
        return await asyncio.wait_for(do_scan(), timeout)

    return None


async def get_scale(args):
    if not args.mac:
        mac = await _scan_for_first_scale(args.scan_time)
        if not mac:
            print("No scale found")
            return
    else:
        mac = args.mac

    return WyzeScale(mac)


async def list_users(args):
    scale = await get_scale(args)
    if not scale:
        return

    async with scale:
        users = await scale.get_users()
        if users is not None and len(users) == 0:
            print("No users on scale")
        for user in users:
            print(user)


async def list_weights(args):
    scale = await get_scale(args)
    if not scale:
        return

    async with scale:
        users = await scale.get_users()

        async def list_weights_for_user(user_data):
            weight_count = 0
            async for weight in scale.get_weights(user_data):
                print("Weight record: %s" % weight)
                weight_count += 1
            return weight_count

        if args.user:
            target_user = bytes.fromhex(args.user)
            target_user_data = None

            for user in users:
                if user.user_id == target_user:
                    target_user_data = user
                    break

            if target_user_data is None:
                _LOGGER.error("User %s not found." % args.user)
            weights = await list_weights_for_user(target_user_data)
            if not weights:
                print("No weights returned")
        else:
            weights = 0
            for user in users:
                weights += await list_weights_for_user(user)
            if not weights:
                print("No weights returned")


async def new_user(args):
    scale = await get_scale(args)
    if not scale:
        return

    async with scale:
        result = await scale.new_user(
            args.user,
            args.weight,
            args.sex,
            args.age,
            args.height,
            args.athlete,
            args.only_weight,
            args.last_impedance)
        if not result:
            _LOGGER.error("Error creating user")


async def delete_user(args):
    scale = await get_scale(args)
    if not scale:
        return

    async with scale:
        result = await scale.delete_user(args.user)
        if not result:
            _LOGGER.error("Error deleting user")


async def reset_scale(args):
    scale = await get_scale(args)
    if not scale:
        return

    async with scale:
        result = await scale.reset_scale()
        if not result:
            _LOGGER.error("Error resetting scale.")


async def set_unit(args):
    scale = await get_scale(args)
    if not scale:
        return

    async with scale:
        result = await scale.set_unit(args.unit == "lb")
        if not result:
            _LOGGER.error("Error setting the units.")


async def set_greeting(args):
    scale = await get_scale(args)
    if not scale:
        return

    async with scale:
        result = await scale.set_greeting(args.greeting)
        if not result:
            _LOGGER.error("Error setting the greeting.")


async def live_weigh(args):
    scale = await get_scale(args)
    if not scale:
        return

    if scale:
        if args.unit is None:
            show_pounds = True
        else:
            show_pounds = args.unit == "lb"

        async with scale:
            async for weight in scale.live_weigh():
                if show_pounds:
                    print("%flb" % weight.weight_lbs)
                else:
                    print("%fkg" % weight.weight_kgs)


class ArgumentFormatError(Exception):
    def __init__(self, *args):
        super(self).__init__(*args)


class MacAction(argparse.Action):
    def __init__(self,
                 option_strings,
                 dest,
                 default=None,
                 type=None,
                 choices=None,
                 required=False,
                 help=None,
                 metavar=None):

        super().__init__(
            option_strings=option_strings,
            dest=dest,
            nargs=1,
            default=default,
            type=type,
            choices=choices,
            required=required,
            help=help,
            metavar=metavar)

    def __call__(self, parser, namespace, values, option_string=None):
        if option_string in self.option_strings:
            pattern = re.compile(
                "^[0-9a-fA-f]{2}:[0-9a-fA-f]{2}:[0-9a-fA-f]{2}:[0-9a-fA-f]{2}:[0-9a-fA-f]{2}:[0-9a-fA-f]{2}$")
            if not values or not pattern.match(values[0]):
                raise argparse.ArgumentError(argument=self,
                                             message="Invalid MAC address. Expecting, e.g. 01:23:45:67:89:ab")
            setattr(namespace, self.dest, values[0])


class UserIdAction(argparse.Action):
    def __init__(self,
                 option_strings,
                 dest,
                 default=None,
                 type=None,
                 choices=None,
                 required=False,
                 help=None,
                 metavar=None):

        super().__init__(
            option_strings=option_strings,
            dest=dest,
            nargs=1,
            default=default,
            type=type,
            choices=choices,
            required=required,
            help=help,
            metavar=metavar)

    def __call__(self, parser, namespace, values, option_string=None):
        if option_string in self.option_strings:
            pattern = re.compile("^[0-9a-fA-f]{32}$")
            if not values or not pattern.match(values[0]):
                raise argparse.ArgumentError(argument=self,
                                             message="Invalid user id. Expecting a 16-byte hexadecimal value."
                                                     " e.g. 0123456789abcdef0123456789abcdef")
            setattr(namespace, self.dest, values[0])


class BoolAction(argparse.Action):
    def __init__(self,
                 option_strings,
                 dest,
                 default=True,
                 type=None,
                 choices=None,
                 required=False,
                 help=None,
                 metavar=None):

        super().__init__(
            option_strings=option_strings,
            dest=dest,
            nargs='?',
            default=default,
            type=type,
            choices=choices,
            required=required,
            help=help,
            metavar=metavar)

    def __call__(self, parser, namespace, values, option_string=None):
        if option_string in self.option_strings:
            if isinstance(values, bool):
                setattr(namespace, self.dest, True)
                return

            if values is None:
                setattr(namespace, self.dest, self.default)
                return

            value_str = values.lower()
            if value_str in ("true", "1"):
                value = True
            elif value_str in ("false", "0"):
                value = False
            else:
                raise argparse.ArgumentError(argument=self,
                                             message="Invalid value. Expecting one of True, False, 0, 1")
            setattr(namespace, self.dest, value)


async def async_main():
    parser = argparse.ArgumentParser(
        description="Utility for reading from and controlling a wyze scale.",
        formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.set_defaults(command=None)

    parser.add_argument("--mac", action=MacAction, help="The bluetooth MAC address of the scale. If no MAC is provided,"
                                                        "it will perform a scan and use the first device found.")
    parser.add_argument("--verbose", "-v", action='count', default=0,
                        help="Print verbose logging. Specify multiple times for more verbocity.")
    parser.add_argument("--version", action="version", version=wyze_scale_tool.__version__,
                        help="Show the version and exit.")

    subparsers = parser.add_subparsers()

    scan_parser = subparsers.add_parser("scan", help="Scan for a wyze scale.")
    scan_parser.add_argument("--multiple", action="store_true",
                             help="Don't return after the first scale is found, but continue scanning for multiple "
                                  "scales.")
    scan_parser.add_argument("--verbose", "-v", action='count', dest="sub_verbose", default=0,
                             help=argparse.SUPPRESS)
    scan_parser.add_argument("--scan_time", "-t", type=int, default=15, help="Number of seconds to scan for")
    scan_parser.set_defaults(func=scan, command="scan_time")

    users_parser = subparsers.add_parser("users", help="Get a list of users.")
    users_parser.add_argument("--verbose", "-v", action='count', dest="sub_verbose", default=0,
                              help=argparse.SUPPRESS)
    users_parser.add_argument("--scan_time", "-t", type=int, default=15, help="Number of seconds to scan for")
    users_parser.set_defaults(func=list_users, command="users")

    weights_parser = subparsers.add_parser("weights", help="Get a list of cached weights for a specific user.")
    weights_parser.add_argument("--user", type=str, action=UserIdAction,
                                help="The user_id of the user to list cached weights for. If not specified, lists the "
                                     "cached weights of all users.")
    weights_parser.add_argument("--scan_time", "-t", type=int, default=15, help="Number of seconds to scan for")
    weights_parser.add_argument("--verbose", "-v", action='count', dest="sub_verbose", default=0,
                                help=argparse.SUPPRESS)
    weights_parser.set_defaults(func=list_weights, command="weights")

    new_user_parser = subparsers.add_parser("new_user", help="Add a user to the scale, or modify an existing user.")
    new_user_parser.add_argument("--user", type=str, action=UserIdAction, required=True,
                                 help="The user_id of the user to create.")
    new_user_parser.add_argument("--weight", type=float, default=0,
                                 help="The weight of the user to create, in kg. Defaults to 0 if not provided.")
    new_user_parser.add_argument("--sex", type=str, default='M',
                                 help="M or F. The sex of the user to create. Defaults to M if not provided.")
    new_user_parser.add_argument("--age", type=int, default=0,
                                 help="The age of the user to create. Defaults to 0 if not provided.")
    new_user_parser.add_argument("--height", type=int, default=0,
                                 help="The height of the user to create, in cm. Defaults to 0 if not provided.")
    new_user_parser.add_argument("--athlete", action=BoolAction,
                                 help="Whether to use athlete mode when weighing this user. Defaults to False if not "
                                      "provided.")
    new_user_parser.add_argument("--only_weight", action=BoolAction,
                                 help="If true, only measure weight, but not impedance, etc. Defaults to False if not "
                                      "provided.")
    new_user_parser.add_argument("--last_impedance", type=int, default=0,
                                 help="The last impedance of this user. Defaults to 0 if not provided.")
    new_user_parser.add_argument("--scan_time", "-t", type=int, default=15, help="Number of seconds to scan for")
    new_user_parser.add_argument("--verbose", "-v", action='count', dest="sub_verbose", default=0,
                                 help=argparse.SUPPRESS)
    new_user_parser.set_defaults(func=new_user, command="new_user")

    delete_user_parser = subparsers.add_parser("delete_user", help="Delete a user from the scale.")
    delete_user_parser.add_argument("--user", type=str, action=UserIdAction, required=True,
                                    help="The user_id of the user to delete.")
    delete_user_parser.add_argument("--scan_time", "-t", type=int, default=15, help="Number of seconds to scan for")
    delete_user_parser.add_argument("--verbose", "-v", action='count', dest="sub_verbose", default=0,
                                    help=argparse.SUPPRESS)
    delete_user_parser.set_defaults(func=delete_user, command="delete_user")

    reset_parser = subparsers.add_parser("reset", help="Factory resets the scale.")
    reset_parser.add_argument("--scan_time", "-t", type=int, default=15, help="Number of seconds to scan for")
    reset_parser.add_argument("--verbose", "-v", action='count', dest="sub_verbose", default=0,
                              help=argparse.SUPPRESS)
    reset_parser.set_defaults(func=reset_scale, command="reset")

    set_unit_parser = subparsers.add_parser("set_unit", help="Change the units displayed on the scale.")
    unit_group = set_unit_parser.add_mutually_exclusive_group(required=True)
    unit_group.add_argument("--lb", action="store_const", const="lb", dest="unit", help="Pounds")
    unit_group.add_argument("--kg", action="store_const", const="kg", dest="unit", help="Kilograms")
    set_unit_parser.add_argument("--scan_time", "-t", type=int, default=15, help="Number of seconds to scan for")
    set_unit_parser.add_argument("--verbose", "-v", action='count', dest="sub_verbose", default=0,
                                 help=argparse.SUPPRESS)
    set_unit_parser.set_defaults(func=set_unit, command="set_unit")

    set_greeting_parser = subparsers.add_parser("set_greeting",
                                                help="Changes whether the scale displays a greeting every time the "
                                                     "screen turns on.")
    set_greeting_parser.add_argument("--greeting", action=BoolAction,
                                     help="If true, a greeting will be displayed every time the screen turns on.")
    set_greeting_parser.add_argument("--scan_time", "-t", type=int, default=15, help="Number of seconds to scan for")
    set_greeting_parser.add_argument("--verbose", "-v", action='count', dest="sub_verbose", default=0,
                                     help=argparse.SUPPRESS)
    set_greeting_parser.set_defaults(func=set_greeting, command="set_greeting")

    live_weigh_parser = subparsers.add_parser("live_weigh",
                                              help="Continuously reads the current weight from the scale.")
    unit_group = live_weigh_parser.add_mutually_exclusive_group()
    unit_group.add_argument("--lb", action="store_const", const="lb", dest="unit",
                            help="Show the weight in pounds (default)")
    unit_group.add_argument("--kg", action="store_const", const="kg", dest="unit", help="Show the weight in kilograms")
    live_weigh_parser.add_argument("--scan_time", "-t", type=int, default=15, help="Number of seconds to scan for")
    live_weigh_parser.add_argument("--verbose", "-v", action='count', dest="sub_verbose", default=0,
                                   help=argparse.SUPPRESS)
    live_weigh_parser.set_defaults(func=live_weigh, command="live_weigh")

    args = parser.parse_args()

    verbose_count = args.verbose
    if hasattr(args, "sub_verbose"):
        verbose_count += args.sub_verbose

    if verbose_count == 1:
        logging.basicConfig(level=logging.WARNING)
        _LOGGER.setLevel(logging.INFO)
    elif verbose_count == 2:
        logging.basicConfig(level=logging.WARNING)
        _LOGGER.setLevel(logging.DEBUG)
    elif verbose_count == 3:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING)

    if not args.command:
        parser.print_usage()
    else:
        await args.func(args)


def main():
    try:
        asyncio.run(async_main())
    except asyncio.CancelledError:
        pass
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
