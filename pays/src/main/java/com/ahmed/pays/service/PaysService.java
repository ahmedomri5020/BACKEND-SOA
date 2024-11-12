package com.ahmed.pays.service;

import java.util.List;
import com.ahmed.pays.entities.Pays;

public interface PaysService {

    Pays savePays(Pays m);
    Pays updatePays(Pays m);
    void deletePays(Pays m);
    void deletePaysById(Long id);
    Pays getPays(Long id);
    List<Pays> getAllPays();
    List<Pays> findByName(String name);
    List<Pays> findByNameContains(String name);
    List<Pays> findByOrderByNameAsc();
    Pays getPaysById(Long id);
}