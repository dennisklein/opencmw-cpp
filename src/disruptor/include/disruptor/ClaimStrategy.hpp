#ifndef OPENCMW_CPP_CLAIMSTRATEGY_HPP
#define OPENCMW_CPP_CLAIMSTRATEGY_HPP

#include <disruptor/Sequence.hpp>
#include <disruptor/SpinWait.hpp>
#include <disruptor/WaitStrategy.hpp>

namespace opencmw::disruptor {

template<std::size_t SIZE, WaitStrategyConcept WAIT_STRATEGY>
class alignas(kCacheLine) SingleThreadedStrategy {
    alignas(kCacheLine) Sequence &_cursor;
    alignas(kCacheLine) WAIT_STRATEGY &_waitStrategy;
    alignas(kCacheLine) std::int64_t _nextValue{ kInitialCursorValue }; // N.B. no need for atomics since this is called by a single publisher
    alignas(kCacheLine) mutable std::int64_t _cachedValue{ kInitialCursorValue };

public:
    SingleThreadedStrategy(Sequence &cursor, WAIT_STRATEGY &waitStrategy)
        : _cursor(cursor), _waitStrategy(waitStrategy){};
    SingleThreadedStrategy(const SingleThreadedStrategy &)  = delete;
    SingleThreadedStrategy(const SingleThreadedStrategy &&) = delete;
    void operator=(const SingleThreadedStrategy &) = delete;

    bool hasAvailableCapacity(const std::vector<std::shared_ptr<Sequence>> &dependents, const int requiredCapacity, const std::int64_t /*cursorValue*/) const noexcept {
        if (const std::int64_t wrapPoint = (_nextValue + requiredCapacity) - static_cast<std::int64_t>(SIZE); wrapPoint > _cachedValue || _cachedValue > _nextValue) {
            auto minSequence = detail::getMinimumSequence(dependents, _nextValue);
            _cachedValue     = minSequence;
            if (wrapPoint > minSequence) {
                return false;
            }
        }
        return true;
    }

    std::int64_t next(const std::vector<std::shared_ptr<Sequence>> &dependents, const std::int32_t n_slots_to_claim = 1) noexcept {
        assert((n_slots_to_claim > 0 && n_slots_to_claim < static_cast<std::int32_t>(SIZE)) && "n_slots_to_claim must be > 0 and < bufferSize");

        auto nextSequence = _nextValue + n_slots_to_claim;
        auto wrapPoint    = nextSequence - static_cast<std::int64_t>(SIZE);

        if (const auto cachedGatingSequence = _cachedValue; wrapPoint > cachedGatingSequence || cachedGatingSequence > _nextValue) {
            _cursor.setValue(_nextValue);

            SpinWait     spinWait;
            std::int64_t minSequence;
            while (wrapPoint > (minSequence = detail::getMinimumSequence(dependents, _nextValue))) {
                if constexpr (requires { _waitStrategy.signalAllWhenBlocking(); }) {
                    _waitStrategy.signalAllWhenBlocking();
                }
                spinWait.spinOnce();
            }
            _cachedValue = minSequence;
        }
        _nextValue = nextSequence;

        return nextSequence;
    }

    std::int64_t tryNext(const std::vector<std::shared_ptr<Sequence>> &dependents, const std::int32_t n_slots_to_claim) {
        assert((n_slots_to_claim > 0) && "n_slots_to_claim must be > 0");

        if (!hasAvailableCapacity(dependents, n_slots_to_claim, 0 /* unused cursor value */)) {
            throw NoCapacityException();
        }

        const auto nextSequence = _nextValue + n_slots_to_claim;
        _nextValue              = nextSequence;

        return nextSequence;
    }

    std::int64_t getRemainingCapacity(const std::vector<std::shared_ptr<Sequence>> &dependents) const noexcept {
        const auto consumed = detail::getMinimumSequence(dependents, _nextValue);
        const auto produced = _nextValue;

        return static_cast<std::int64_t>(SIZE) - (produced - consumed);
    }

    void publish(std::int64_t sequence) {
        _cursor.setValue(sequence);
        if constexpr (requires { _waitStrategy.signalAllWhenBlocking(); }) {
            _waitStrategy.signalAllWhenBlocking();
        }
    }

    [[nodiscard]] forceinline bool isAvailable(std::int64_t sequence) const noexcept { return sequence <= _cursor.value(); }
    [[nodiscard]] std::int64_t     getHighestPublishedSequence(std::int64_t /*nextSequence*/, std::int64_t availableSequence) const noexcept { return availableSequence; }
};

/**
 * Claim strategy for claiming sequences for access to a data structure while tracking dependent Sequences.
 * Suitable for use for sequencing across multiple publisher threads.
 * Note on cursor:  With this sequencer the cursor value is updated after the call to SequencerBase::next(),
 * to determine the highest available sequence that can be read, then getHighestPublishedSequence should be used.
 */
template<std::size_t SIZE, WaitStrategyConcept WAIT_STRATEGY>
class MultiThreadedStrategy {
    alignas(kCacheLine) Sequence &_cursor;
    alignas(kCacheLine) WAIT_STRATEGY &_waitStrategy;
    alignas(kCacheLine) std::array<std::int32_t, SIZE> _availableBuffer; // tracks the state of each ringbuffer slot
    alignas(kCacheLine) std::shared_ptr<Sequence> _gatingSequenceCache = std::make_shared<Sequence>();
    static constexpr std::int32_t _indexMask                           = SIZE - 1;
    static constexpr std::int32_t _indexShift                          = ceillog2(SIZE);

public:
    MultiThreadedStrategy() = delete;
    explicit MultiThreadedStrategy(Sequence &cursor, WAIT_STRATEGY &waitStrategy)
        : _cursor(cursor), _waitStrategy(waitStrategy) {
        for (std::size_t i = SIZE - 1; i != 0; i--) {
            setAvailableBufferValue(i, -1);
        }
        setAvailableBufferValue(0, -1);
    }
    MultiThreadedStrategy(const MultiThreadedStrategy &)  = delete;
    MultiThreadedStrategy(const MultiThreadedStrategy &&) = delete;
    void               operator=(const MultiThreadedStrategy &) = delete;

    [[nodiscard]] bool hasAvailableCapacity(const std::vector<std::shared_ptr<Sequence>> &dependents, const std::int64_t requiredCapacity, const std::int64_t cursorValue) const noexcept {
        const auto wrapPoint = (cursorValue + requiredCapacity) - static_cast<std::int64_t>(SIZE);

        if (const auto cachedGatingSequence = _gatingSequenceCache->value(); wrapPoint > cachedGatingSequence || cachedGatingSequence > cursorValue) {
            const auto minSequence = detail::getMinimumSequence(dependents, cursorValue);
            _gatingSequenceCache->setValue(minSequence);

            if (wrapPoint > minSequence) {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] std::int64_t next(const std::vector<std::shared_ptr<Sequence>> &dependents, const std::int32_t n_slots_to_claim = 1) {
        assert((n_slots_to_claim > 0) && "n_slots_to_claim must be > 0");

        std::int64_t current;
        std::int64_t next;

        SpinWait     spinWait;
        do {
            current                           = _cursor.value();
            next                              = current + n_slots_to_claim;

            std::int64_t wrapPoint            = next - static_cast<std::int64_t>(SIZE);
            std::int64_t cachedGatingSequence = _gatingSequenceCache->value();

            if (wrapPoint > cachedGatingSequence || cachedGatingSequence > current) {
                std::int64_t gatingSequence = detail::getMinimumSequence(dependents, current);

                if (wrapPoint > gatingSequence) {
                    if constexpr (requires { _waitStrategy.signalAllWhenBlocking(); }) {
                        _waitStrategy.signalAllWhenBlocking();
                    }
                    spinWait.spinOnce();
                    continue;
                }

                _gatingSequenceCache->setValue(gatingSequence);
            } else if (_cursor.compareAndSet(current, next)) {
                break;
            }
        } while (true);

        return next;
    }

    [[nodiscard]] std::int64_t tryNext(const std::vector<std::shared_ptr<Sequence>> &dependents, const std::int32_t n_slots_to_claim = 1) {
        assert((n_slots_to_claim > 0) && "n_slots_to_claim must be > 0");

        std::int64_t current;
        std::int64_t next;

        do {
            current = _cursor.value();
            next    = current + n_slots_to_claim;

            if (!hasAvailableCapacity(dependents, n_slots_to_claim, current)) {
                throw NoCapacityException();
            }
        } while (!_cursor.compareAndSet(current, next));

        return next;
    }

    [[nodiscard]] std::int64_t getRemainingCapacity(const std::vector<std::shared_ptr<Sequence>> &dependents) const noexcept {
        const auto produced = _cursor.value();
        const auto consumed = detail::getMinimumSequence(dependents, produced);

        return static_cast<std::int64_t>(SIZE) - (produced - consumed);
    }

    void publish(std::int64_t sequence) {
        setAvailable(sequence);
        if constexpr (requires { _waitStrategy.signalAllWhenBlocking(); }) {
            _waitStrategy.signalAllWhenBlocking();
        }
    }

    [[nodiscard]] forceinline bool isAvailable(std::int64_t sequence) const noexcept {
        const auto index = calculateIndex(sequence);
        const auto flag  = calculateAvailabilityFlag(sequence);

        return _availableBuffer[static_cast<std::size_t>(index)] == flag;
    }

    [[nodiscard]] forceinline std::int64_t getHighestPublishedSequence(const std::int64_t lowerBound, const std::int64_t availableSequence) const noexcept {
        for (std::int64_t sequence = lowerBound; sequence <= availableSequence; sequence++) {
            if (!isAvailable(sequence)) {
                return sequence - 1;
            }
        }

        return availableSequence;
    }

private:
    void                      setAvailable(std::int64_t sequence) noexcept { setAvailableBufferValue(calculateIndex(sequence), calculateAvailabilityFlag(sequence)); }
    forceinline void          setAvailableBufferValue(std::size_t index, std::int32_t flag) noexcept { _availableBuffer[index] = flag; }
    [[nodiscard]] forceinline std::int32_t calculateAvailabilityFlag(const std::int64_t sequence) const noexcept { return static_cast<std::int32_t>(static_cast<std::uint64_t>(sequence) >> _indexShift); }
    [[nodiscard]] forceinline std::size_t calculateIndex(const std::int64_t sequence) const noexcept { return static_cast<std::size_t>(static_cast<std::int32_t>(sequence) & _indexMask); }
};

template<std::size_t SIZE, typename WAIT_STRATEGY>
class MultiThreadedStrategy2 {
    alignas(kCacheLine) Sequence &_cursor;
    alignas(kCacheLine) WAIT_STRATEGY &_waitStrategy;
    alignas(kCacheLine) Sequence last_claimed_sequence_;
    alignas(kCacheLine) Sequence last_consumer_sequence_;

public:
    MultiThreadedStrategy2()                                = default;
    MultiThreadedStrategy2(const MultiThreadedStrategy2 &)  = delete;
    MultiThreadedStrategy2(const MultiThreadedStrategy2 &&) = delete;
    void    operator=(const MultiThreadedStrategy2 &) = delete;

    int64_t IncrementAndGet(const std::vector<std::shared_ptr<Sequence>> &dependents,
            size_t                                                        delta = 1) {
        const int64_t next_sequence = last_claimed_sequence_.addAndGet(delta);
        const int64_t wrap_point    = next_sequence - SIZE;
        if (last_consumer_sequence_.value() < wrap_point) {
            while (detail::getMinimumSequence(dependents) < wrap_point) {
                // xTODO: configurable yield strategy
                std::this_thread::yield();
            }
        }
        return next_sequence;
    }

    bool hasAvailableCapacity(const std::vector<std::shared_ptr<Sequence>> &dependents, const int requiredCapacity) {
        const int64_t wrap_point = last_claimed_sequence_.value() + requiredCapacity - SIZE;
        if (wrap_point > last_consumer_sequence_.value()) {
            const int64_t min_sequence = detail::getMinimumSequence(dependents);
            last_consumer_sequence_.setValue(min_sequence);
            if (wrap_point > min_sequence) return false;
        }
        return true;
    }

    void publish(const std::int64_t &sequence, const Sequence &cursor, const std::int32_t n_slots_to_claim = 1) {
        const std::int64_t my_first_sequence = sequence - n_slots_to_claim;

        while (cursor.value() < my_first_sequence) {
            // xTODO: configurable yield strategy
            std::this_thread::yield();
        }
    }
};

} // namespace opencmw::disruptor

#endif // OPENCMW_CPP_CLAIMSTRATEGY_HPP
