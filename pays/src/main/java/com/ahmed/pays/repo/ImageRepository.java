package com.ahmed.pays.repo;
import org.springframework.data.jpa.repository.JpaRepository;
import com.ahmed.pays.entities.Image;


public interface ImageRepository extends JpaRepository<Image , Long> {
}