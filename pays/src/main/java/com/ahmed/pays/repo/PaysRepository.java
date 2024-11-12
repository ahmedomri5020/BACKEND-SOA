package com.ahmed.pays.repo;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.ahmed.pays.entities.Pays;

public interface PaysRepository extends JpaRepository<Pays, Long> {

    List<Pays> findByNomPays(String nomPays);

    List<Pays> findByNomPaysContains(String nomPays);

    List<Pays> findByOrderByNomPaysAsc();
}
