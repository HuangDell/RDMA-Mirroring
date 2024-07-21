# convert ns(hex type) to minutes
def nanoseconds_to_minutes(hex_nanoseconds):
    nanoseconds = int(hex_nanoseconds, 16)
    
    seconds_in_minute = 60
    milliseconds_in_second = 1e-3
    microseconds_in_millisecond = 1e-3
    nanoseconds_in_microsecond = 1e-3
    seconds = nanoseconds * nanoseconds_in_microsecond * microseconds_in_millisecond * milliseconds_in_second
    minutes = seconds / seconds_in_minute

    return minutes

hex_nanoseconds = "0x0206ddd84ec0"  
minutes = nanoseconds_to_minutes(hex_nanoseconds)
print(f"{hex_nanoseconds} 纳秒等于 {minutes} 分钟")