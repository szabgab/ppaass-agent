#![cfg(test)]
use std::{error::Error, sync::Arc};

#[derive(Debug)]
struct Left(u32);

#[derive(Debug)]
struct Right(u32);

#[derive(Debug)]
struct Test {
    left: Arc<Left>,
    right: Arc<Right>,
}

impl Test {
    pub fn into_split(self) -> (Arc<Left>, Arc<Right>) {
        let left = self.left.clone();
        let right = self.right.clone();
        (left, right)
    }
}

impl Drop for Test {
    fn drop(&mut self) {
        println!("#### Drop test: {self:?}")
    }
}

#[test]
fn test() -> Result<(), Box<dyn Error>> {
    println!("#### Begin test");
    let test = Test {
        left: Arc::new(Left(1)),
        right: Arc::new(Right(2)),
    };
    let (left, right) = test.into_split();
    println!("#### After test leak");
    println!("#### Test left: {left:?}, right: {right:?}");
    // drop(_t);
    Ok(())
}
