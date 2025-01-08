from datetime import datetime

def convert_time_string(time_str):
    time_obj = datetime.strptime(time_str, "%H:%M:%S")
    
    hours = time_obj.hour
    minutes = time_obj.minute
    seconds = time_obj.second

    time_parts = []
    if hours > 0:
        time_parts.append(f"{hours} hour{'s' if hours > 1 else ''}")
    if minutes > 0:
        time_parts.append(f"{minutes} minute{'s' if minutes > 1 else ''}")
    if seconds > 0 or (hours == 0 and minutes == 0):
        time_parts.append(f"{seconds} second{'s' if seconds != 1 else ''}")

    return " ".join(time_parts)
