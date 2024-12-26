
    select
        name,
        ip
    from
        email.dynamic_dns
       where status = 'active'
       