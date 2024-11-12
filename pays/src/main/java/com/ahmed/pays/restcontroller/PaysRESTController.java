package com.ahmed.pays.restcontroller;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.ahmed.pays.entities.Pays;
import com.ahmed.pays.service.PaysService;

@CrossOrigin(origins = "http://localhost:4200")
@RestController
@RequestMapping("/api/pays")
public class PaysRESTController {

    @Autowired
    private PaysService paysService;

    @GetMapping
    public ResponseEntity<Map<String, Object>> getAllPays() {
        List<Pays> paysList = paysService.getAllPays();
        Map<String, Object> response = new HashMap<>();
        response.put("_embedded", Collections.singletonMap("pays", paysList));
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @GetMapping("/{id}")
    public ResponseEntity<Pays> getPaysById(@PathVariable("id") Long id) {
        Pays pays = paysService.getPays(id);
        if (pays != null) {
            return new ResponseEntity<>(pays, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    @PostMapping
    public ResponseEntity<Pays> createPays(@RequestBody Pays pays) {
        Pays createdPays = paysService.savePays(pays);
        return new ResponseEntity<>(createdPays, HttpStatus.CREATED);
    }

    @PutMapping("/{id}")
    public ResponseEntity<Pays> updatePays(@PathVariable("id") Long id, @RequestBody Pays pays) {
        pays.setIdPays(id);
        Pays updatedPays = paysService.updatePays(pays);
        if (updatedPays != null) {
            return new ResponseEntity<>(updatedPays, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deletePaysById(@PathVariable("id") Long id) {
        if (paysService.getPays(id) != null) {
            paysService.deletePaysById(id);
            return new ResponseEntity<>(HttpStatus.NO_CONTENT);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    @GetMapping("/search/name")
    public List<Pays> findPaysByName(@RequestParam("name") String nomPays) {
        return paysService.findByName(nomPays);
    }

    @GetMapping("/search/nameContains")
    public List<Pays> findPaysByNameContains(@RequestParam("name") String nomPays) {
        return paysService.findByNameContains(nomPays);
    }

    @GetMapping("/sort")
    public List<Pays> sortPaysByName() {
        return paysService.findByOrderByNameAsc();
    }
}
