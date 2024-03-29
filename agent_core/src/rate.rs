use serde::{Deserialize, Serialize};
use std::cmp::{max, Ordering};
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::ops::Deref;
use std::time::{Duration, SystemTime};

use hsm_api::RecordId;

const RESERVATION_LIFETIME: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub struct RateLimitResult {
    pub used: usize,
    pub limit: usize,
    pub reservation: bool,
    pub allowed: bool,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PeerId(pub String);

#[derive(Debug)]
pub struct RateLimiter {
    rate: usize, // reqs / second
    my_reqs: OrderedVecDeque<SystemTime>,
    others_reqs: OrderedVecDeque<SystemTime>,
    reservations: Reservations,
}

impl RateLimiter {
    pub fn new(http_reqs_per_second: usize) -> Self {
        RateLimiter {
            my_reqs: OrderedVecDeque::default(),
            others_reqs: OrderedVecDeque::default(),
            rate: http_reqs_per_second,
            reservations: Reservations::default(),
        }
    }

    pub fn update_limit(&mut self, new_reqs_per_second: usize) {
        self.rate = new_reqs_per_second;
    }

    pub fn allow(&mut self, id: RecordId) -> RateLimitResult {
        self.allow_inner(SystemTime::now(), id)
    }

    fn allow_inner(&mut self, now: SystemTime, rec: RecordId) -> RateLimitResult {
        let window_start = now - Duration::from_secs(1);
        self.my_reqs.remove_smaller(&window_start);
        self.others_reqs.remove_smaller(&window_start);
        let used = self.my_reqs.len() + self.others_reqs.len();
        let ok = used < self.rate;

        let reservation = self.reservations.use_reservation(now, rec);
        if ok || reservation {
            self.my_reqs.add(now);
        }
        RateLimitResult {
            used,
            limit: self.rate,
            reservation,
            allowed: ok || reservation,
        }
    }

    pub fn add_reservation(&mut self, id: RecordId) {
        self.add_reservation_inner(SystemTime::now(), id)
    }

    fn add_reservation_inner(&mut self, now: SystemTime, id: RecordId) {
        self.reservations.add(now + RESERVATION_LIFETIME, id)
    }

    /// Returns the current state such that it can be serialized and given to other nodes.
    pub fn state(&mut self, now: SystemTime) -> State {
        let expire_before = now - RESERVATION_LIFETIME * 2;
        self.reservations
            .used
            .retain(|(tm, _id)| *tm >= expire_before);

        State {
            reqs: self.my_reqs.clone(),
            reservations: self.reservations.mine.clone(),
            reservations_used: self.reservations.used.clone(),
        }
    }

    pub fn update_from_peers(&mut self, state: MergedStates) {
        self.others_reqs = state.0.reqs;
        self.reservations.others = state.0.reservations;
        self.reservations.used_others = state.0.reservations_used;
    }
}

#[derive(Debug, Default)]
pub struct PeerStates(HashMap<PeerId, (SystemTime, State)>);
impl PeerStates {
    pub fn update(&mut self, now: SystemTime, from: PeerId, state: State) {
        self.0.insert(from, (now, state));
    }

    pub fn merged(&mut self, now: SystemTime) -> MergedStates {
        let exp = now - RESERVATION_LIFETIME;
        self.0.retain(|_peer, (when, _state)| *when > exp);
        let states: Vec<_> = self.0.values().map(|(_, s)| s.clone()).collect();
        MergedStates::merge(states)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct State {
    reqs: OrderedVecDeque<SystemTime>,
    reservations: ReservationSet,
    reservations_used: HashSet<(SystemTime, RecordId)>,
}

pub struct MergedStates(State);

impl MergedStates {
    pub fn merge(mut peers: Vec<State>) -> Self {
        if peers.is_empty() {
            return MergedStates(State::default());
        }
        if peers.len() == 1 {
            return MergedStates(peers.pop().unwrap());
        }
        let mut reqs = Vec::with_capacity(peers.len());
        let mut res = Vec::with_capacity(peers.len());
        let mut used =
            HashSet::with_capacity(peers.iter().map(|p| p.reservations_used.len()).sum());
        for peer in peers {
            reqs.push(peer.reqs);
            res.push(peer.reservations);
            used.extend(peer.reservations_used);
        }
        let r = State {
            reqs: OrderedVecDeque::merge(reqs),
            reservations: ReservationSet::merge(res),
            reservations_used: used,
        };
        MergedStates(r)
    }
}

#[derive(Debug, Default)]
struct Reservations {
    mine: ReservationSet,
    others: ReservationSet,
    // recent reservations that were used locally. These are kept an additional
    // RESERVATION_LIFETIME amount of time. We expect all nodes to trade state
    // multiple times within that time period. This allows all the nodes a
    // chance to spot that a reservation was consumed.
    used: HashSet<(SystemTime, RecordId)>,
    // Generally reservations will be used on the agent which made the
    // reservation but events like leadership transfer can lead to the
    // reservation being used on a different agent.
    used_others: HashSet<(SystemTime, RecordId)>,
}

impl Reservations {
    fn add(&mut self, expires: SystemTime, id: RecordId) {
        self.mine.add_reservation(expires, id);
    }

    fn use_reservation(&mut self, now: SystemTime, id: RecordId) -> bool {
        let mut reserved = self.mine.use_reservation(&now, &id);
        if reserved.is_none() {
            reserved = self.others.use_reservation(&now, &id);
        }
        if let Some(tm) = reserved {
            if !self.used.insert((tm, id.clone())) {
                // this reservation was already used
                reserved = None;
            } else {
                // check it wasn't used elsewhere
                let key = (tm, id);
                if self.used_others.contains(&key) {
                    reserved = None;
                }
            }
        }
        reserved.is_some()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct ReservationSet {
    expiry: OrderedVecDeque<Expiry>,
    ids: HashMap<RecordId, SystemTime>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct Expiry {
    when: SystemTime,
    id: RecordId,
}

impl PartialOrd for Expiry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Expiry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.when.cmp(&other.when)
    }
}

impl ReservationSet {
    fn merge(items: Vec<ReservationSet>) -> ReservationSet {
        let mut exp = Vec::with_capacity(items.len());
        let mut ids = HashMap::with_capacity(items.iter().map(|r| r.ids.len()).sum());
        for i in items {
            exp.push(i.expiry);
            ids.extend(i.ids);
        }
        ReservationSet {
            expiry: OrderedVecDeque::merge(exp),
            ids,
        }
    }

    // expire all entries that are before 'upto'
    fn expire(&mut self, upto: &SystemTime) {
        while self.expiry.front().is_some_and(|e| e.when < *upto) {
            let expiry = self.expiry.pop_front().unwrap();
            if let Occupied(e) = self.ids.entry(expiry.id) {
                if e.get() == &expiry.when {
                    e.remove();
                }
            }
        }
    }

    fn use_reservation(&mut self, now: &SystemTime, id: &RecordId) -> Option<SystemTime> {
        self.expire(now);
        self.ids.remove(id)
    }

    fn add_reservation(&mut self, exp: SystemTime, id: RecordId) {
        match self.ids.entry(id.clone()) {
            Occupied(mut e) => {
                // If there's an existing reservation, move the time forward
                let entry_tm = e.get_mut();
                *entry_tm = max(*entry_tm, exp);
            }
            Vacant(e) => {
                e.insert(exp);
            }
        }
        self.expiry.add(Expiry { when: exp, id });
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct OrderedVecDeque<T>(VecDeque<T>);

impl<T> Default for OrderedVecDeque<T> {
    fn default() -> Self {
        Self(Default::default())
    }
}

impl<T> Deref for OrderedVecDeque<T> {
    type Target = VecDeque<T>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Ord> OrderedVecDeque<T> {
    fn merge(items: Vec<OrderedVecDeque<T>>) -> Self {
        let mut r = VecDeque::with_capacity(items.iter().map(|q| q.len()).sum());
        for mut i in items {
            r.append(&mut i.0);
        }
        r.make_contiguous().sort();
        OrderedVecDeque(r)
    }

    fn pop_front(&mut self) -> Option<T> {
        self.0.pop_front()
    }

    // remove all entries that are before 'upto'
    fn remove_smaller(&mut self, upto: &T) {
        while self.0.front().is_some_and(|t| t < upto) {
            self.0.pop_front();
        }
    }

    fn add(&mut self, item: T) {
        if Some(&item) >= self.0.back() {
            //  common case, `item` is larger than anything we've seen before
            self.0.push_back(item);
        } else {
            let pos = match self.0.binary_search(&item) {
                Ok(p) => p,
                Err(p) => p,
            };
            self.0.insert(pos, item);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::iter::zip;
    use std::time::{Duration, SystemTime};

    use super::{
        MergedStates, OrderedVecDeque, PeerId, RateLimiter, ReservationSet, State,
        RESERVATION_LIFETIME,
    };
    use hsm_api::RecordId;

    #[test]
    fn remove_smaller() {
        let mut r = OrderedVecDeque::default();
        let n = SystemTime::now();
        r.add(n);
        r.add(n);
        r.add(millis(n, 10));
        assert_eq!(3, r.len());
        assert!(!r.is_empty());

        r.add(millis(n, 11));
        assert_eq!(4, r.len());
        r.remove_smaller(&millis(n, 10));
        assert_eq!(2, r.len());
        r.remove_smaller(&millis(n, 10));
        assert_eq!(2, r.len());
        r.remove_smaller(&millis(n, 11));
        assert_eq!(1, r.len());
        r.remove_smaller(&millis(n, 12));
        assert_eq!(0, r.len());
    }

    #[test]
    fn ordered_add() {
        let mut r = OrderedVecDeque::default();
        let n = SystemTime::now();
        r.add(n);
        r.add(millis(n, 10));
        r.add(n);
        r.add(millis(n, 2));
        r.add(millis(n, 12));
        r.add(millis(n, 2));
        assert_eq!(6, r.len());
        let mut p = r.0[0];
        for next in r.0.iter().skip(1) {
            assert!(*next >= p);
            p = *next;
        }
    }

    #[test]
    fn reservations_use() {
        let mut r = ReservationSet::default();
        let id = RecordId([3; 32]);
        let now = SystemTime::now();
        let exp = now + RESERVATION_LIFETIME;
        assert_eq!(None, r.use_reservation(&now, &id));

        // Can only use reservation once.
        r.add_reservation(exp, id.clone());
        assert_eq!(Some(exp), r.use_reservation(&millis(now, 10), &id));
        assert_eq!(None, r.use_reservation(&millis(now, 10), &id));

        // Shouldn't get the reservation if we're past the expiry time when
        // trying to use it.
        r.add_reservation(exp, id.clone());
        assert_eq!(1, r.ids.len());
        assert_eq!(None, r.use_reservation(&millis(exp, 2), &id));
        assert!(r.ids.is_empty());

        // There's only one reservation per record id, the highest expiry time is kept.
        r.add_reservation(exp, id.clone());
        r.add_reservation(millis(exp, 10), id.clone());
        r.add_reservation(millis(exp, 5), id.clone());
        assert_eq!(
            Some(millis(exp, 10)),
            r.use_reservation(&millis(now, 100), &id)
        );
        assert_eq!(None, r.use_reservation(&millis(now, 101), &id));
    }

    fn rid(i: u8) -> RecordId {
        RecordId([i; 32])
    }

    #[test]
    fn local_allow() {
        let mut rl = RateLimiter::new(5);
        let now = SystemTime::now();

        assert!(rl.allow_inner(now, rid(1)).allowed);
        assert!(rl.allow_inner(millis(now, 10), rid(2)).allowed);
        assert!(rl.allow_inner(millis(now, 20), rid(3)).allowed);
        assert!(rl.allow_inner(millis(now, 30), rid(4)).allowed);
        assert!(rl.allow_inner(millis(now, 40), rid(5)).allowed);

        assert!(!rl.allow_inner(millis(now, 50), rid(6)).allowed);
        assert!(!rl.allow_inner(millis(now, 999), rid(7)).allowed);

        // first request should now be outside the 1 second window.
        assert!(rl.allow_inner(millis(now, 1005), rid(7)).allowed);
        assert!(!rl.allow_inner(millis(now, 1006), rid(8)).allowed);

        // if the record id has a reservation, that should be allowed.
        rl.add_reservation_inner(millis(now, 1007), rid(9));
        assert!(!rl.allow_inner(millis(now, 1008), rid(10)).allowed);
        assert!(rl.allow_inner(millis(now, 1008), rid(9)).allowed);
        // but its only good for one call
        assert!(!rl.allow_inner(millis(now, 1009), rid(9)).allowed);

        // the reserved call still counts in the window, so we can't make other
        // requests until 2 more items have expires
        assert!(!rl.allow_inner(millis(now, 1015), rid(11)).allowed);
        assert!(rl.allow_inner(millis(now, 1025), rid(11)).allowed);
    }

    fn millis(t: SystemTime, millis: u64) -> SystemTime {
        t + Duration::from_millis(millis)
    }

    #[test]
    fn distributed_limiters() {
        let mut limiters: Vec<_> = (0..3).map(|_| RateLimiter::new(5)).collect();
        let node_ids: Vec<PeerId> = ["a", "b", "c"]
            .into_iter()
            .map(|s| PeerId(String::from(s)))
            .collect();
        let now = SystemTime::now();

        for rl in &mut limiters {
            assert!(rl.allow_inner(now, rid(32)).allowed);
        }
        trade_limiter_state(now, &node_ids, &mut limiters);
        // everyone should think there's been 3 requests out of the allowed 5
        assert!(limiters[0].allow_inner(millis(now, 10), rid(33)).allowed);
        assert!(limiters[0].allow_inner(millis(now, 20), rid(34)).allowed);
        assert!(!limiters[0].allow_inner(millis(now, 30), rid(35)).allowed);

        // within the sync window, the limit can't be breached locally, but
        // can be breached globally
        assert!(limiters[1].allow_inner(millis(now, 40), rid(33)).allowed);
        assert!(limiters[1].allow_inner(millis(now, 50), rid(34)).allowed);
        assert!(!limiters[1].allow_inner(millis(now, 60), rid(35)).allowed);

        // after a sync, they should all agree now that the limit is reached.
        trade_limiter_state(millis(now, 60), &node_ids, &mut limiters);
        for rl in &mut limiters {
            assert!(!rl.allow_inner(millis(now, 70), rid(36)).allowed);
        }
        // items from other buckets should get expired
        // currently there's a total of 7 requests in the 0...1000 window
        assert!(!limiters[2].allow_inner(millis(now, 999), rid(46)).allowed);
        // 3 of those should get expired at 1000. 4 left allows one more.
        assert!(limiters[2].allow_inner(millis(now, 1005), rid(47)).allowed);
        assert!(!limiters[2].allow_inner(millis(now, 1006), rid(48)).allowed);

        // 1 more expired at 1010
        assert!(limiters[2].allow_inner(millis(now, 1011), rid(49)).allowed);
    }

    #[test]
    fn distributed_limiters_with_reservations() {
        let mut limiters: Vec<_> = (0..3).map(|_| RateLimiter::new(5)).collect();
        let node_ids: Vec<PeerId> = ["a", "b", "c"]
            .into_iter()
            .map(|s| PeerId(String::from(s)))
            .collect();
        let now = SystemTime::now();

        for rl in &mut limiters {
            assert!(rl.allow_inner(now, rid(1)).allowed);
            assert!(rl.allow_inner(millis(now, 1), rid(2)).allowed);
            assert!(rl.allow_inner(millis(now, 2), rid(3)).allowed);
        }
        trade_limiter_state(millis(now, 3), &node_ids, &mut limiters);
        // over the limit now everywhere
        for rl in &mut limiters {
            assert!(!rl.allow_inner(millis(now, 10), rid(4)).allowed);
        }
        // get a reservation
        limiters[0].add_reservation_inner(millis(now, 10), rid(45));
        // use the reservation
        assert!(limiters[0].allow_inner(millis(now, 20), rid(45)).allowed);

        trade_limiter_state(millis(now, 20), &node_ids, &mut limiters);
        // still over the limit everywhere
        for rl in &mut limiters {
            assert!(!rl.allow_inner(millis(now, 30), rid(4)).allowed);
        }
        // and the reservation is used up
        for rl in &mut limiters {
            assert!(!rl.allow_inner(millis(now, 30), rid(45)).allowed);
        }

        // get a reservation on one node, then use it from another
        limiters[0].add_reservation_inner(millis(now, 50), rid(46));
        trade_limiter_state(millis(now, 51), &node_ids, &mut limiters);
        assert!(limiters[2].allow_inner(millis(now, 60), rid(46)).allowed);
        assert!(!limiters[2].allow_inner(millis(now, 62), rid(46)).allowed);

        // after a sync, everyone should know the reservation was used
        trade_limiter_state(millis(now, 64), &node_ids, &mut limiters);
        for rl in &mut limiters {
            assert!(!rl.allow_inner(millis(now, 65), rid(46)).allowed);
        }
    }

    fn trade_limiter_state(now: SystemTime, ids: &[PeerId], limiters: &mut [RateLimiter]) {
        assert_eq!(ids.len(), limiters.len());
        let states: Vec<(&PeerId, Vec<u8>)> = zip(
            ids,
            limiters
                .iter_mut()
                .map(|b| b.state(now))
                .map(|s| juicebox_marshalling::to_vec(&s).unwrap()),
        )
        .collect();

        for i in 0..ids.len() {
            let other_stats: Vec<State> = states
                .iter()
                .filter(|(id, _)| **id != ids[i])
                .map(|(_, s)| juicebox_marshalling::from_slice(s).unwrap())
                .collect();
            let merged = MergedStates::merge(other_stats);
            limiters[i].update_from_peers(merged);
        }
    }
}
