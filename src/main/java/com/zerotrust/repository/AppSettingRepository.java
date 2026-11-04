package com.zerotrust.repository;

import org.springframework.data.mongodb.repository.MongoRepository;

import com.zerotrust.entity.AppSetting;

public interface AppSettingRepository extends MongoRepository<AppSetting, String> {
}
