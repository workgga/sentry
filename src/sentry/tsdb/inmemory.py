"""
sentry.tsdb.inmemory
~~~~~~~~~~~~~~~~~~~~

:copyright: (c) 2010-2014 by the Sentry Team, see AUTHORS for more details.
:license: BSD, see LICENSE for more details.
"""
from __future__ import absolute_import

from collections import Counter, defaultdict

import six
from django.utils import timezone

from sentry.tsdb.base import BaseTSDB
from sentry.utils.dates import to_datetime, to_timestamp


class InMemoryTSDB(BaseTSDB):
    """
    An in-memory time-series storage.

    This should not be used in production as it will leak memory.
    """

    def __init__(self, *args, **kwargs):
        super(InMemoryTSDB, self).__init__(*args, **kwargs)
        self.flush()

    def incr(self, model, key, timestamp=None, count=1, environment_id=None):
        environment_ids = set([environment_id, None])

        if timestamp is None:
            timestamp = timezone.now()

        for rollup, max_values in six.iteritems(self.rollups):
            norm_epoch = self.normalize_to_rollup(timestamp, rollup)
            for environment_id in environment_ids:
                self.data[model][(key, environment_id)][norm_epoch] += count

    def merge(self, model, destination, sources, timestamp=None, environment_ids=None):
        environment_ids = (
            set(environment_ids) if environment_ids is not None else set()).union(
            [None])

        for environment_id in environment_ids:
            destination = self.data[model][(destination, environment_id)]
            for source in sources:
                for bucket, count in self.data[model].pop((source, environment_id), {}).items():
                    destination[bucket] += count

    def delete(self, models, keys, start=None, end=None, timestamp=None, environment_ids=None):
        environment_ids = (
            set(environment_ids) if environment_ids is not None else set()).union(
            [None])

        rollups = self.get_active_series(start, end, timestamp)

        for rollup, series in rollups.items():
            for model in models:
                for key in keys:
                    for environment_id in environment_ids:
                        data = self.data[model][(key, environment_id)]
                        for timestamp in series:
                            data.pop(
                                self.normalize_to_rollup(timestamp, rollup),
                                0,
                            )

    def get_range(self, model, keys, start, end, rollup=None, environment_id=None):
        rollup, series = self.get_optimal_rollup_series(start, end, rollup)

        results = []
        for timestamp in map(to_datetime, series):
            norm_epoch = self.normalize_to_rollup(timestamp, rollup)

            for key in keys:
                value = self.data[model][(key, environment_id)][norm_epoch]
                results.append((to_timestamp(timestamp), key, value))

        results_by_key = defaultdict(dict)
        for epoch, key, count in results:
            results_by_key[key][epoch] = int(count or 0)

        for key, points in six.iteritems(results_by_key):
            results_by_key[key] = sorted(points.items())
        return dict(results_by_key)

    def record(self, model, key, values, timestamp=None, environment_id=None):
        environment_ids = set([environment_id, None])

        if timestamp is None:
            timestamp = timezone.now()

        for rollup, max_values in six.iteritems(self.rollups):
            r = self.normalize_to_rollup(timestamp, rollup)
            for environment_id in environment_ids:
                self.sets[model][(key, environment_id)][r].update(values)

    def get_distinct_counts_series(self, model, keys, start, end=None,
                                   rollup=None, environment_id=None):
        rollup, series = self.get_optimal_rollup_series(start, end, rollup)

        results = {}
        for key in keys:
            source = self.sets[model][(key, environment_id)]
            counts = results[key] = []
            for timestamp in series:
                r = self.normalize_ts_to_rollup(timestamp, rollup)
                counts.append((timestamp, len(source[r])))

        return results

    def get_distinct_counts_totals(self, model, keys, start, end=None,
                                   rollup=None, environment_id=None):
        rollup, series = self.get_optimal_rollup_series(start, end, rollup)

        results = {}
        for key in keys:
            source = self.sets[model][(key, environment_id)]
            values = set()
            for timestamp in series:
                r = self.normalize_ts_to_rollup(timestamp, rollup)
                values.update(source[r])
            results[key] = len(values)

        return results

    def get_distinct_counts_union(self, model, keys, start, end=None,
                                  rollup=None, environment_id=None):
        rollup, series = self.get_optimal_rollup_series(start, end, rollup)

        values = set()
        for key in keys:
            source = self.sets[model][(key, environment_id)]
            for timestamp in series:
                r = self.normalize_ts_to_rollup(timestamp, rollup)
                values.update(source[r])

        return len(values)

    def merge_distinct_counts(self, model, destination, sources,
                              timestamp=None, environment_ids=None):
        environment_ids = (
            set(environment_ids) if environment_ids is not None else set()).union(
            [None])

        for environment_id in environment_ids:
            destination = self.sets[model][(destination, environment_id)]
            for source in sources:
                for bucket, values in self.sets[model].pop((source, environment_id), {}).items():
                    destination[bucket].update(values)

    def delete_distinct_counts(self, models, keys, start=None, end=None,
                               timestamp=None, environment_ids=None):
        environment_ids = (
            set(environment_ids) if environment_ids is not None else set()).union(
            [None])

        rollups = self.get_active_series(start, end, timestamp)

        for rollup, series in rollups.items():
            for model in models:
                for key in keys:
                    for environment_id in environment_ids:
                        data = self.data[model][(key, environment_id)]
                        for timestamp in series:
                            data.pop(
                                self.normalize_to_rollup(timestamp, rollup),
                                set(),
                            )

    def flush(self):
        # self.data[model][key][rollup] = count
        self.data = defaultdict(
            lambda: defaultdict(
                lambda: defaultdict(
                    int,
                )
            )
        )

        # self.sets[model][key][rollup] = set of elements
        self.sets = defaultdict(
            lambda: defaultdict(
                lambda: defaultdict(
                    set,
                ),
            ),
        )

        # self.frequencies[model][key][rollup] = Counter()
        self.frequencies = defaultdict(
            lambda: defaultdict(
                lambda: defaultdict(
                    Counter,
                )
            ),
        )

    def record_frequency_multi(self, requests, timestamp=None, environment_id=None):
        environment_ids = set([environment_id, None])

        if timestamp is None:
            timestamp = timezone.now()

        for model, request in requests:
            for key, items in request.items():
                items = {k: float(v) for k, v in items.items()}
                for environment_id in environment_ids:
                    source = self.frequencies[model][(key, environment_id)]
                    for rollup in self.rollups:
                        source[self.normalize_to_rollup(timestamp, rollup)].update(items)

    def get_most_frequent(self, model, keys, start, end=None,
                          rollup=None, limit=None, environment_id=None):
        rollup, series = self.get_optimal_rollup_series(start, end, rollup)

        results = {}
        for key in keys:
            result = results[key] = Counter()
            source = self.frequencies[model][(key, environment_id)]
            for timestamp in series:
                result.update(source[self.normalize_ts_to_rollup(timestamp, rollup)])

        for key, counter in results.items():
            results[key] = counter.most_common(limit)

        return results

    def get_most_frequent_series(self, model, keys, start, end=None,
                                 rollup=None, limit=None, environment_id=None):
        rollup, series = self.get_optimal_rollup_series(start, end, rollup)

        results = {}
        for key in keys:
            result = results[key] = []
            source = self.frequencies[model][(key, environment_id)]
            for timestamp in series:
                data = source[self.normalize_ts_to_rollup(timestamp, rollup)]
                result.append((timestamp, dict(data.most_common(limit))))

        return results

    def get_frequency_series(self, model, items, start, end=None, rollup=None, environment_id=None):
        rollup, series = self.get_optimal_rollup_series(start, end, rollup)

        results = {}
        for key, members in items.items():
            result = results[key] = []
            source = self.frequencies[model][(key, environment_id)]
            for timestamp in series:
                scores = source[self.normalize_ts_to_rollup(timestamp, rollup)]
                result.append((timestamp, {k: scores.get(k, 0.0) for k in members}, ))

        return results

    def get_frequency_totals(self, model, items, start, end=None, rollup=None, environment_id=None):
        results = {}

        for key, series in six.iteritems(
            self.get_frequency_series(model, items, start, end, rollup, environment_id)
        ):
            result = results[key] = {}
            for timestamp, scores in series:
                for member, score in scores.items():
                    result[member] = result.get(member, 0.0) + score

        return results

    def merge_frequencies(self, model, destination, sources, timestamp=None, environment_ids=None):
        environment_ids = (
            set(environment_ids) if environment_ids is not None else set()).union(
            [None])

        for environment_id in environment_ids:
            destination = self.frequencies[model][(destination, environment_id)]
            for source in sources:
                for bucket, counter in self.data[model].pop((source, environment_id), {}).items():
                    destination[bucket].update(counter)

    def delete_frequencies(self, models, keys, start=None, end=None,
                           timestamp=None, environment_ids=None):
        environment_ids = (
            set(environment_ids) if environment_ids is not None else set()).union(
            [None])

        rollups = self.get_active_series(start, end, timestamp)

        for rollup, series in rollups.items():
            for model in models:
                for key in keys:
                    for environment_id in environment_ids:
                        data = self.frequencies[model][(key, environment_id)]
                        for timestamp in series:
                            data.pop(
                                self.normalize_to_rollup(timestamp, rollup),
                                Counter(),
                            )
