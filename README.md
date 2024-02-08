# wyze_scale_tool - A utility for reading from and managing a Wyze Scale X

This is a proof-of-concept python library and stand-alone program
for communicating with a Wyze Scale X.

## Installation

```pip install wyze_scale_tool```

## CLI Usage

The CLI interface supports most of the functionality of the protocol, including creating, modifying and deleting users, 
querying weights, changing scale settings (units, etc.), and even a live-weighing mode that continuously
shows the current measured weight from the scale.

### Example Usage

To get a list of all cached weights of all users on the scale

```wyze_scale_tool weights```

To explore more of the options that are available, you can use --help

```wyze_scale_tool --help```

## API Usage

This also exposes an API that can be used to communicate with a Wyze Scale X

```python
import asyncio

from wyze_scale_tool import WyzeScale

async def main():
    mac_address = "AA:BB:CC:DD:EE:FF"

    scale = WyzeScale(mac_address)

    async with scale:
        users = await scale.get_users()
        for user in users:
            async for weight in scale.get_weights(user):
                print("User: %s Time: %s Weight: %s" % (
                    bytes.hex(user.user_id), weight.timestamp_str(), weight.weight_lbs))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except asyncio.CancelledError:
        pass
```