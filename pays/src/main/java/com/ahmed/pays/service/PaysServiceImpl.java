package com.ahmed.pays.service;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.ahmed.pays.entities.Pays;
import com.ahmed.pays.repo.PaysRepository;

@Service // This annotation marks the class as a Spring service component
public class PaysServiceImpl implements PaysService {

    @Autowired
    private PaysRepository paysRepository;

    @Override
    public Pays savePays(Pays pays) {
        return paysRepository.save(pays);
    }

    @Override
    public Pays updatePays(Pays pays) {
        return paysRepository.save(pays);
    }

    @Override
    public void deletePays(Pays pays) {
        paysRepository.delete(pays);
    }

    @Override
    public void deletePaysById(Long id) {
        paysRepository.deleteById(id);
    }

    @Override
    public Pays getPays(Long id) {
        return paysRepository.findById(id).orElse(null);
    }

    @Override
    public List<Pays> getAllPays() {
        return paysRepository.findAll();
    }

    @Override
    public List<Pays> findByName(String name) {
        return paysRepository.findByNomPays(name);
    }

    @Override
    public List<Pays> findByNameContains(String name) {
        return paysRepository.findByNomPaysContains(name);
    }

    @Override
    public List<Pays> findByOrderByNameAsc() {
        return paysRepository.findByOrderByNomPaysAsc();
    }

    @Override
    public Pays getPaysById(Long id) {
        return getPays(id); // This can be simplified by reusing the getPays method
    }
}
