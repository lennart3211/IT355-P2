package com.ticketapp.assign;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

/**
 * Owner: (unassigned)
 *
 * In-process per-ticket locks. NOTE: these only protect one JVM; across service
 * instances the DB conditional UPDATE / version column is the real guard (CWE-821).
 *
 * CWE-820 Missing Synchronization: all ticket mutations go through withLock().
 * CWE-821 Incorrect Synchronization: ONE lock object per ticket id, shared by every
 *   code path (computeIfAbsent), never a new lock per call.
 * CWE-833 Deadlock: withLocks() sorts ids ascending before acquiring, and releases
 *   in finally. Optionally use tryLock(timeout).
 */
public class TicketLockManager {

    private final ConcurrentHashMap<Long, ReentrantLock> locks = new ConcurrentHashMap<>();

    public <T> T withLock(long ticketId, Supplier<T> action) {
        ReentrantLock lock = locks.computeIfAbsent(ticketId, id -> new ReentrantLock());
        lock.lock();
        try {
            return action.get();
        } finally {
            lock.unlock();
        }
    }

    /** Acquire multiple ticket locks in stable (ascending id) order — e.g. for merge. */
    public <T> T withLocks(long[] ticketIds, Supplier<T> action) {
        // TODO: copy + sort ids; dedupe; lock each in order; run; unlock in reverse in finally
        throw new UnsupportedOperationException("TODO");
    }
}
