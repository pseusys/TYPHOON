use std::time::Duration;

use tokio::spawn;
use tokio::time::sleep;

#[cfg(feature = "server")]
use crate::utils::sync::create_bounded_notify_queue;
use crate::utils::sync::{create_notify_queue, create_watch};

// ── WatchSender / WatchReceiver ──────────────────────────────────────────────

// Test: value sent before recv() is available immediately.
#[tokio::test]
async fn test_watch_send_before_recv() {
    let (tx, mut rx) = create_watch::<u32>();
    tx.send(42);
    assert_eq!(rx.recv().await, Some(42));
}

// Test: recv() blocks until a value is sent.
#[tokio::test]
async fn test_watch_recv_blocks_until_send() {
    let (tx, mut rx) = create_watch::<u32>();
    let handle = spawn(async move { rx.recv().await });
    sleep(Duration::from_millis(10)).await;
    tx.send(99);
    assert_eq!(handle.await.unwrap(), Some(99));
}

// Test: latest-value-wins — only the last sent value is received.
#[tokio::test]
async fn test_watch_latest_value_wins() {
    let (tx, mut rx) = create_watch::<u32>();
    tx.send(1);
    tx.send(2);
    tx.send(3);
    assert_eq!(rx.recv().await, Some(3));
}

// Test: recv() returns None after the sender is dropped.
#[tokio::test]
async fn test_watch_sender_drop_closes_receiver() {
    let (tx, mut rx) = create_watch::<u32>();
    drop(tx);
    assert_eq!(rx.recv().await, None);
}

// Test: a value sent before recv() is polled is not lost (the enable() pre-registration guards this).
#[cfg(feature = "client")]
#[tokio::test]
async fn test_watch_pre_registered_waiter_does_not_miss_send() {
    let (tx, _) = create_watch::<u32>();
    // subscribe() creates a receiver for future sends.
    let mut rx = tx.subscribe();
    // Send before recv() is ever polled.
    tx.send(77);
    assert_eq!(rx.recv().await, Some(77));
}

// ── NotifyQueueSender / NotifyQueueReceiver ───────────────────────────────────

// Test: items are received in FIFO order.
#[tokio::test]
async fn test_notify_queue_fifo_order() {
    let (tx, mut rx) = create_notify_queue::<u32>();
    tx.push(1);
    tx.push(2);
    tx.push(3);
    assert_eq!(rx.recv().await, Some(1));
    assert_eq!(rx.recv().await, Some(2));
    assert_eq!(rx.recv().await, Some(3));
}

// Test: recv() wakes up when an item is pushed.
#[tokio::test]
async fn test_notify_queue_recv_wakes_on_push() {
    let (tx, mut rx) = create_notify_queue::<u32>();
    let handle = spawn(async move { rx.recv().await });
    sleep(Duration::from_millis(10)).await;
    tx.push(55);
    assert_eq!(handle.await.unwrap(), Some(55));
}

// Test: recv() returns None once the sender is dropped and the queue is empty.
#[tokio::test]
async fn test_notify_queue_sender_drop_closes_receiver() {
    let (tx, mut rx) = create_notify_queue::<u32>();
    tx.push(1);
    drop(tx);
    assert_eq!(rx.recv().await, Some(1));
    assert_eq!(rx.recv().await, None);
}

// ── BoundedNotifyQueueSender / BoundedNotifyQueueReceiver ────────────────────

// Test: items within capacity are received in FIFO order.
#[cfg(feature = "server")]
#[tokio::test]
async fn test_bounded_queue_fifo_within_capacity() {
    let (tx, mut rx) = create_bounded_notify_queue::<u32>(4);
    tx.push(10);
    tx.push(20);
    tx.push(30);
    assert_eq!(rx.recv().await, Some(10));
    assert_eq!(rx.recv().await, Some(20));
    assert_eq!(rx.recv().await, Some(30));
}

// Test: items pushed beyond capacity are silently dropped.
#[cfg(feature = "server")]
#[tokio::test]
async fn test_bounded_queue_drops_on_full() {
    let (tx, mut rx) = create_bounded_notify_queue::<u32>(2);
    tx.push(1);
    tx.push(2);
    tx.push(3); // dropped — queue full
    assert_eq!(rx.recv().await, Some(1));
    assert_eq!(rx.recv().await, Some(2));
    // No third item.
    drop(tx);
    assert_eq!(rx.recv().await, None);
}

// Test: recv() wakes the receiver when an item is pushed to a bounded queue.
#[cfg(feature = "server")]
#[tokio::test]
async fn test_bounded_queue_recv_wakes_on_push() {
    let (tx, mut rx) = create_bounded_notify_queue::<u32>(8);
    let handle = spawn(async move { rx.recv().await });
    sleep(Duration::from_millis(10)).await;
    tx.push(42);
    assert_eq!(handle.await.unwrap(), Some(42));
}
