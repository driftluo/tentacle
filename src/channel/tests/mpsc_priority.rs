use crate::channel::mpsc;
use futures::executor::block_on;
use futures::stream::StreamExt;

#[test]
fn send_recv() {
    let (tx, rx) = mpsc::channel::<i32>(16);
    tx.try_send(2).unwrap();
    tx.try_quick_send(1).unwrap();
    tx.try_send(3).unwrap();
    tx.try_send(4).unwrap();
    tx.try_quick_send(6).unwrap();
    tx.try_send(5).unwrap();

    drop(tx);
    let v: Vec<_> = block_on(rx.map(|item| item.1).collect());
    assert_eq!(v, vec![1, 6, 2, 3, 4, 5]);
}

#[test]
fn send_recv_unbound() {
    let (tx, rx) = mpsc::unbounded::<i32>();
    tx.unbounded_send(2).unwrap();
    tx.unbounded_quick_send(1).unwrap();
    tx.unbounded_send(3).unwrap();
    tx.unbounded_send(4).unwrap();
    tx.unbounded_quick_send(6).unwrap();
    tx.unbounded_send(5).unwrap();

    drop(tx);
    let v: Vec<_> = block_on(rx.map(|item| item.1).collect());
    assert_eq!(v, vec![1, 6, 2, 3, 4, 5]);
}
