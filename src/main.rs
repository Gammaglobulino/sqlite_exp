extern crate bcrypt;
use bcrypt::{hash,verify,BcryptError};

use sqlite::Error as SqErr;

pub struct UserBase{
    fname:String,
}
#[derive(Debug)]
pub enum UBaseErr{
    DbErr(SqErr),
    HashError(BcryptError),
}
impl From<SqErr> for UBaseErr{
    fn from(s:SqErr)->Self{
        UBaseErr::DbErr(s)
    }
}
impl From<BcryptError> for UBaseErr{
    fn from(b:BcryptError)->Self{
        UBaseErr::HashError(b)
    }
}

impl UserBase{
    pub fn add_user(&self,u_name:&str, pwd:&str)->Result<(),UBaseErr>{
        let conn=sqlite::open(&self.fname)?;
        let hpass=bcrypt::hash(pwd,8)?;
        
        let mut st=conn.prepare("insert into users (u_name,p_word) values(?,?);")?;
        st.bind(1, u_name)?;
        st.bind(2, &hpass as &str)?;
        st.next()?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct User{
    uname:String,
    pass_hash:String,
}

impl User{
    pub fn new(uname:String,pwd:&str)->Result<User,BcryptError>{
        Ok(User{
            uname,
            pass_hash:hash(pwd,10)?,
        })
    }
    pub fn verify(&self,pwd:&str)->bool{
        verify(pwd, &self.pass_hash).unwrap_or(false)
    }
}

fn main() {
    let u=User::new(String::from("Andrea Mazzanti"), "andrea_pw").unwrap();
    println!("User created {:?}",u);
    println!("User verified pwd {}:{}","andrea_pw",u.verify("andrea_pw"));
    println!("User verified wrong pwd {}:{}","andrea_pwc",u.verify("andrea_pwc"));
}

#[cfg(test)]
mod test{
    use super::*;
    #[test]
    fn add_user_test(){
        let ub=UserBase{fname:String::from("data/users.db")};
        ub.add_user("Andrea Mazzanti","anndrea_pw").unwrap();

    }
}