from tls_gateway.session_cache import SessionCache, SessionInfo


def _info(sid: str, epoch: int = 0) -> SessionInfo:
    return SessionInfo(session_id=sid, vhost="h.example", epoch=epoch, has_ticket=False)


def test_capacity_bounds_growth():
    cache = SessionCache(3)
    for i in range(10):
        cache.put(_info(str(i)))
    assert len(cache) == 3


def test_lru_eviction_order():
    cache = SessionCache(3)
    for sid in ("a", "b", "c"):
        cache.put(_info(sid))
    assert cache.get("a") is not None  # touch a -> b is now oldest
    cache.put(_info("d"))
    assert cache.get("b") is None
    assert cache.get("a") is not None and cache.get("c") is not None


def test_rotation_invalidates_all_and_bumps_epoch():
    cache = SessionCache(4)
    cache.put(_info("a"))
    new_epoch = cache.rotate()
    assert new_epoch == 1
    assert cache.epoch == 1
    assert len(cache) == 0
    assert cache.get("a") is None


def test_entries_from_old_epoch_rejected():
    cache = SessionCache(4)
    cache.rotate()  # epoch 1
    cache.put(_info("stale", epoch=0))
    assert len(cache) == 0
    assert cache.get("stale") is None


def test_discard():
    cache = SessionCache(4)
    cache.put(_info("a"))
    cache.discard("a")
    assert cache.get("a") is None


def test_long_running_rotation_cycle_keeps_bound():
    cache = SessionCache(16)
    for r in range(5):
        for i in range(100):
            cache.put(_info(f"{r}-{i}", epoch=cache.epoch))
        assert len(cache) <= 16
        cache.rotate()
    assert len(cache) == 0
