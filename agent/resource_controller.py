from agent.system_metrics import get_cpu_usage, get_memory_usage
from agent.resource_limits import (
    CPU_HIGH, CPU_RESUME,
    MEM_HIGH, MEM_RESUME
)

class ResourceController:
    def __init__(self):
        self.paused = False

    def should_pause(self):
        cpu = get_cpu_usage()
        mem = get_memory_usage()

        if cpu > CPU_HIGH or mem > MEM_HIGH:
            self.paused = True
            return True

        return False

    def should_resume(self):
        cpu = get_cpu_usage()
        mem = get_memory_usage()

        if cpu < CPU_RESUME and mem < MEM_RESUME:
            self.paused = False
            return True

        return False
