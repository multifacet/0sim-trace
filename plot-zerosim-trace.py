#!/usr/bin/env python3

import matplotlib.pyplot as plt
import matplotlib.patches as patches
import matplotlib.lines as lines
import numpy as np
import re
import random

from sys import argv

RE=r'''(\d+) { ([\w?_]+)\s+(\w+)?\s+ts: (\d+), flags:\s+(\d+), id: (\d+) }'''

FREQ=3.5E3

INTERVAL_HEIGHT=0.3

START_MARKER='>'
END_MARKER='<'

filename = argv[1]

data = {}
min_ts = None
max_ts = None

with open(filename, 'r') as f:
    for line in f.readlines():
        m = re.match(RE, line)

        if m is None:
            print("No match for line: %s" % line)

        core = int(m.group(1))
        event = m.group(2)
        start = m.group(3) is not None
        ts = int(m.group(4)) / FREQ # usec
        flags = int(m.group(5), 2)  # binary
        ev_id = int(m.group(6))

        if core not in data:
            data[core] = []

        if start == 0 and ts == 0 and flags == 0 and ev_id == 0:
            continue

        data[core].append((event, start, ts, flags, ev_id))

        if min_ts is None or ts < min_ts:
            min_ts = ts
        if max_ts is None or ts > max_ts:
            max_ts = ts

# Process to get matching events
for cpu, cpu_data in data.items():
    matched = []

    # stack of pending events
    pending = []

    for ev in cpu_data:
        #print(ev)

        # handle open events
        if ev[1]:
            pending.append(ev)
            continue

        # handle close events
        else:
            # if the event matches something on the stack, match it. Otherwise,
            # push a singleton event.
            if len(pending) > 0 and ev[0] == pending[-1][0] and ev[4] == pending[-1][4]:
                start = pending.pop()
                matched.append(("interval", ev[0], start[2], ev[2], ev[3], ev[4]))
            else:
                matched.append(ev)
    
    # Append all pending events as singletons
    matched.extend(pending)

    data[cpu] = matched
    #data[cpu].extend(matched)

levels = np.array([-5, 5, -3, 3, -1, 1])
fig, ax = plt.subplots(figsize=(8, 5))

# Create a line for each CPU
for cpu in range(len(data)):
    ax.text((min_ts - max_ts) * 0.01, cpu, "CPU%d" % cpu, horizontalalignment='right', verticalalignment='center', fontsize=14)
    ax.plot((0, max_ts - min_ts), (cpu, cpu), 'k', alpha=0.2)

np.random.seed(0)

label_colors = {}

def get_label_color(label):
    if label in label_colors:
        return label_colors[label]
    else:
        label_colors[label] = np.random.rand(3,)
        return get_label_color(label)

#print("====")

# Iterate through releases annotating each one
for cpu, cpu_data in data.items():
    for ev in cpu_data:
        #print(ev)
        if ev[0] == 'interval':
            # intervals (matched events)
            rect = patches.Rectangle((ev[2] - min_ts, cpu - INTERVAL_HEIGHT/2), ev[3] - ev[2], 
                    INTERVAL_HEIGHT, color=get_label_color(ev[1]), fill=True, alpha=0.5)
            ax.add_patch(rect)
        else:
            # point event
            ax.scatter(ev[2] - min_ts, cpu, s=50,
                    c=get_label_color(ev[0]), marker=START_MARKER if ev[1] else END_MARKER, zorder=9999)

        # Plot a line up to the text
        #level = levels[ii % 6]
        #vert = 'top' if level < 0 else 'bottom'
        # ax.plot((idate, idate), (0, level), c='r', alpha=.7)
        # # Give the text a faint background and align it properly
        # ax.text(idate, level, iname,
        #         horizontalalignment='right', verticalalignment=vert, fontsize=14,
        #         backgroundcolor=(1., 1., 1., .3))

# Custom legend
legend_elements = [lines.Line2D([0], [0], markerfacecolor='k', marker=START_MARKER, \
                        markersize=15, color='w', label='Start'),
                   lines.Line2D([0], [0], markerfacecolor='k', marker=END_MARKER, \
                        markersize=15, color='w', label='End'),
                   ]

for label, color in label_colors.items():
    legend_elements.append(lines.Line2D([0], [0], color=color, lw=4, label=label))

ax.legend(handles=legend_elements, bbox_to_anchor=(0,1.02,1,0.2), loc="lower left",
                mode="expand", borderaxespad=0, ncol=3)

# Remove components for a cleaner look
plt.setp((ax.get_yticklabels() + ax.get_yticklines() +
          list(ax.spines.values())), visible=False)
plt.show()
