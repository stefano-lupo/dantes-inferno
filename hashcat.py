import pendulum
import regex
import sarge

from dataclasses import dataclass, field
from enum import Enum
from typing import *
from unipath import Path


class HashcatStatus(Enum):
    RUNNING = 1
    KILLED = 2
    ERROR = 3
    FINISHED = 4


@dataclass
class HashcatProgress:
    status: HashcatStatus
    progress: Tuple[int, int] = (0, 0)
    speed: List[float] = field(default_factory=list)
    recovered: Tuple[int, int] = (0, 0)
    time_started: pendulum.DateTime = pendulum.now()
    eta: pendulum.DateTime = pendulum.now()
    utilisation: float = 0


class Hashcat(object):
    status_re = regex.compile(
        r'^.*$'
        r'^.*$'
        r'^.*$'
        r'^.*$'
        r'^Time\.Started[.: ]*(?P<time_started>[a-zA-Z0-9 :]+) .*$'
        r'^Time\.Estimated[.: ]*(?P<time_estimated>[a-zA-Z0-9 :]+) .*$'
        r'^.*$'
        r'^.*$'
        r'(?:^Speed.* (?P<speed>[\d.]+) (?P<speed_units>\w{1,2})/.*$)+'
        r'^Recovered[.: ]*(?P<recovered>\d+)/(?P<num_hashes>\d+).*$'
        r'^Progress[.: ]*(?P<progress>\d+)/(?P<num_guesses>\d+).*$'
        r'^.*$'
        r'^.*$'
        r'^.*$'
        r'^.*Util:(?P<utilisation>[\d.]+)%.*$',
        regex.MULTILINE
    )

    def __init__(self,
                 hash_type: int,
                 hashes: Path,
                 wordlist: Path,
                 potfile: Path = None):
        self.command = sarge.run(sarge.shell_format(
            'hashcat '
            '-a 0 '
            '-m {0} -O -w 3 '
            '--session={1} '
            '--status '
            '{2!s}'
            '{3} '
            '{4}', [hash_type,
                    'cs4400_practical5_{}_{}'.format(hash_type, wordlist),
                    sarge.shell_format('--potfile {0} ',
                                       potfile) if potfile is not None else '',
                    hashes,
                    wordlist]),
            stdout=sarge.Capture(buffer_size=-1),  # read stdout line-by-line
            stderr=sarge.Capture(buffer_size=-1),  # read stderr line-by-line
            async_=True  # Don't stop me now
        )
        self.status = HashcatStatus.RUNNING

    def kill(self):
        self.command.kill()
        self.command.close()
        self.status = HashcatStatus.KILLED

    def status(self) -> HashcatProgress:
        # Update program status
        if self.status == HashcatStatus.RUNNING \
                and self.command.commands[-1].poll() is not None:
            self.command.close()
            if self.command.returncode == 0:
                self.status = HashcatStatus.FINISHED
            else:
                self.status = HashcatStatus.ERROR

        try:
            output = self.command.stdout.text
        except UnicodeDecodeError:
            # Maybe we are still printing?
            # Let's just not crash first, maybe things will get better
            return HashcatProgress(HashcatStatus.ERROR)

        if 'All hashes found in potfile' in output:
            self.command.close()
            self.status = HashcatStatus.FINISHED
            return HashcatProgress(self.status)

        last_status_index = output.rfind('Status')
        if last_status_index == -1:
            # No status update yet
            return HashcatProgress(self.status)
        match = self.status_re.match(output, pos=last_status_index)
        if not match:
            # No status update, but maybe it hasn't finished printing.
            # Check the one before
            last_status_index = output.rfind('Status', end=last_status_index)
            if last_status_index == -1:
                # No status update before
                return HashcatProgress(self.status)
            match = self.status_re.match(output, pos=last_status_index)
            if not match:
                # No status update found
                # This must mean something smelly
                return HashcatProgress(self.status)

        time_format = 'ddd MMM  D HH:mm:ss YYYY'
        time_started = pendulum.from_format(
            match.group('time_started').replace('  ', ' '),
            time_format)
        eta = pendulum.from_format(
            match.group('time_estimated').replace('  ', ' '),
            time_format)
        speed = [float(s) * 1e9 if u[0] == 'G' else
                 float(s) * 1e6 if u[0] == 'M' else
                 float(s) * 1e3 if u[0] == 'k' else
                 float(s)
                 for s, u in zip(match.captures('speed'),
                                 match.captures('speed_units'))]
        recovered = (int(match.group('recovered')),
                     int(match.group('num_hashes')))
        progress = (int(match.group('progress')),
                    int(match.group('num_guesses')))
        utilisation = float(match.group('utilisation')) / 100

        return HashcatProgress(self.status,
                               progress=progress,
                               speed=speed,
                               recovered=recovered,
                               time_started=time_started,
                               eta=eta,
                               utilisation=utilisation)

    def read_stderr(self) -> List[str]:
        return self.command.stderr.readlines(block=False)
